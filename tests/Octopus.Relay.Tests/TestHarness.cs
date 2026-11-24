using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Octopus.Relay.Api;
using Octopus.Relay.Auth;
using Octopus.Relay.Relay;

namespace Octopus.Relay.Tests;

internal sealed class FakeClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan delta) => _now += delta;
}

internal sealed class TestDevice : IDisposable
{
    private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public TestDevice(string name = "Test Mac", string kind = "desktop")
    {
        Name = name;
        Kind = kind;
        var p = _ecdsa.ExportParameters(includePrivateParameters: false);
        PublicKeyBytes = [0x04, .. p.Q.X!, .. p.Q.Y!];
        PublicKeyBase64 = Convert.ToBase64String(PublicKeyBytes);
        Id = DeviceKey.DeriveId(PublicKeyBytes);
    }

    public string Name { get; }
    public string Kind { get; }
    public byte[] PublicKeyBytes { get; }
    public string PublicKeyBase64 { get; }
    public string Id { get; }

    public string SignBase64(byte[] hash)
    {
        return Convert.ToBase64String(_ecdsa.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    public void Dispose() => _ecdsa.Dispose();
}

internal sealed class RelayTestServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly string? _tempDir;

    private RelayTestServer(WebApplication app, Uri baseUri, string? tempDir)
    {
        _app = app;
        BaseUri = baseUri;
        _tempDir = tempDir;
    }

    public Uri BaseUri { get; }
    public IServiceProvider Services => _app.Services;
    public OwnerAuthService OwnerAuth => _app.Services.GetRequiredService<OwnerAuthService>();
    public RelayHub Hub => _app.Services.GetRequiredService<RelayHub>();

    public static async Task<RelayTestServer> StartAsync(
        Action<ServerSettings>? configureSettings = null,
        FakeClock? clock = null,
        string? dataDir = null,
        bool ownTempDir = false)
    {
        var settings = new ServerSettings
        {
            ListenUrl = "http://127.0.0.1:0",
            DataDir = dataDir,
            PollIntervalSeconds = 1,
        };
        configureSettings?.Invoke(settings);

        var builder = ServerHost.CreateBuilder(settings);
        var app = ServerHost.Build(builder, settings, services =>
        {
            if (clock is not null)
            {
                services.AddSingleton<TimeProvider>(clock);
            }
        });
        app.Urls.Add(settings.ListenUrl);
        await app.StartAsync();
        return new RelayTestServer(app, ServerHost.ListeningUrl(app), ownTempDir ? dataDir : null);
    }

    public HttpClient CreateHttpClient(bool cookies = false)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = cookies,
            CookieContainer = new CookieContainer(),
            AllowAutoRedirect = false,
        };
        return new HttpClient(handler) { BaseAddress = BaseUri };
    }

    public async Task<JsonElement> SignInWithKeyAsync(TestDevice device, string accessKey)
    {
        using var http = CreateHttpClient();
        using var chRes = await http.PostAsync("/v1/auth/key/challenge", new StringContent("{}", Encoding.UTF8, "application/json"));
        chRes.EnsureSuccessStatusCode();
        var chDoc = JsonDocument.Parse(await chRes.Content.ReadAsStringAsync()).RootElement;
        var challengeB64 = chDoc.GetProperty("challenge").GetString()!;
        var sig = device.SignBase64(DeviceKey.KeyLoginHash(Convert.FromBase64String(challengeB64)));

        var payload = JsonSerializer.Serialize(new
        {
            accessKey,
            challenge = challengeB64,
            deviceName = device.Name,
            kind = device.Kind,
            publicKey = device.PublicKeyBase64,
            signature = sig,
            platform = "macOS",
            appVersion = "1.0.1135",
        });
        using var res = await http.PostAsync("/v1/auth/key", new StringContent(payload, Encoding.UTF8, "application/json"));
        res.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    public async Task<ClientWebSocket> ConnectHostAsync(TestDevice host, string accessToken, string[]? features = null)
    {
        var ws = new ClientWebSocket();
        ws.Options.SetRequestHeader("Authorization", "Bearer " + accessToken);
        var wsUri = new UriBuilder(new Uri(BaseUri, "/v1/host")) { Scheme = "ws" }.Uri;
        await ws.ConnectAsync(wsUri, CancellationToken.None);

        var challengeText = await ReceiveTextAsync(ws);
        var nonceB64 = JsonDocument.Parse(challengeText).RootElement.GetProperty("nonce").GetString()!;
        var nonce = Convert.FromBase64String(nonceB64);

        var register = JsonSerializer.Serialize(new
        {
            type = "register",
            publicKey = host.PublicKeyBase64,
            name = host.Name,
            signature = host.SignBase64(DeviceKey.HostRegistrationHash(nonce)),
            features,
        });
        await SendTextAsync(ws, register);

        var registeredText = await ReceiveTextAsync(ws);
        var regDoc = JsonDocument.Parse(registeredText).RootElement;
        if (regDoc.GetProperty("type").GetString() != "registered" || regDoc.GetProperty("deviceId").GetString() != host.Id)
        {
            throw new InvalidOperationException("Unexpected registration response: " + registeredText);
        }

        return ws;
    }

    public async Task<string> RequestTunnelAsync(string accessToken, string hostDeviceId)
    {
        using var http = CreateHttpClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/tunnels");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        req.Content = new StringContent($$"""{"hostDeviceId":"{{hostDeviceId}}"}""", Encoding.UTF8, "application/json");
        using var res = await http.SendAsync(req);
        res.EnsureSuccessStatusCode();
        var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement;
        return doc.GetProperty("tunnel").GetString()!;
    }

    public async Task<ClientWebSocket> JoinTunnelAsync(string tunnelId, string role, string accessToken)
    {
        var ws = new ClientWebSocket();
        ws.Options.SetRequestHeader("Authorization", "Bearer " + accessToken);
        var wsUri = new UriBuilder(new Uri(BaseUri, $"/v1/tunnel/{tunnelId}?role={role}")) { Scheme = "ws" }.Uri;
        await ws.ConnectAsync(wsUri, CancellationToken.None);
        return ws;
    }

    public static Task SendTextAsync(WebSocket ws, string text)
    {
        return ws.SendAsync(Encoding.UTF8.GetBytes(text), WebSocketMessageType.Text, true, CancellationToken.None);
    }

    public static async Task<string> ReceiveTextAsync(WebSocket ws)
    {
        var ms = new MemoryStream();
        var buf = new byte[4096];
        while (true)
        {
            var r = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (r.MessageType == WebSocketMessageType.Close)
            {
                throw new WebSocketException($"Closed: {r.CloseStatus} {r.CloseStatusDescription}");
            }

            ms.Write(buf, 0, r.Count);
            if (r.EndOfMessage)
            {
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }

    public static async Task<byte[]> ReceiveBinaryAsync(WebSocket ws)
    {
        var ms = new MemoryStream();
        var buf = new byte[64 * 1024];
        while (true)
        {
            var r = await ws.ReceiveAsync(buf, CancellationToken.None);
            if (r.MessageType == WebSocketMessageType.Close)
            {
                throw new WebSocketException($"Closed: {r.CloseStatus} {r.CloseStatusDescription}");
            }

            ms.Write(buf, 0, r.Count);
            if (r.EndOfMessage)
            {
                return ms.ToArray();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        if (_tempDir is not null && Directory.Exists(_tempDir))
        {
            try
            {
                Directory.Delete(_tempDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
