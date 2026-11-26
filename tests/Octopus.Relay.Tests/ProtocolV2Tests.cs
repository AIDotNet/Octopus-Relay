using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Octopus.Relay.Api;
using Octopus.Relay.Relay;
using Xunit;

namespace Octopus.Relay.Tests;

public sealed class ProtocolV2Tests
{
    private const string AccessKey = "ork_v2_test_access_key_0123456789abcdef";

    [Fact]
    public async Task Stun_server_answers_rfc5389_binding_request_and_advertises_in_info()
    {
        await using var server = await RelayTestServer.StartAsync(s =>
        {
            s.AccessKey = AccessKey;
            s.StunBindAddress = IPAddress.Loopback;
            s.StunPort = 0;
            s.ExternalStunServers.Add("stun:stun.example.net:3478");
        });

        var stun = server.Services.GetRequiredService<StunServer>();
        Assert.True(stun.IsRunning);
        Assert.NotNull(stun.BoundPort);

        using var http = server.CreateHttpClient();
        using var infoRes = await http.GetAsync("/v1/info");
        infoRes.EnsureSuccessStatusCode();
        var info = JsonDocument.Parse(await infoRes.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(2, info.GetProperty("protocol").GetInt32());
        var transports = info.GetProperty("transports").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("ws", transports);

        var stunServers = info.GetProperty("stunServers").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains($"stun:127.0.0.1:{stun.BoundPort}", stunServers);
        Assert.Contains("stun:stun.example.net:3478", stunServers);

        // Send a real RFC 5389 STUN Binding Request over UDP and verify XOR-MAPPED-ADDRESS.
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var localEp = (IPEndPoint)client.LocalEndPoint!;

        var txId = RandomNumberGenerator.GetBytes(12);
        var request = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(0, 2), 0x0001);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2, 2), 0);
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4, 4), StunServer.MagicCookie);
        txId.CopyTo(request.AsSpan(8, 12));

        var stunEp = new IPEndPoint(IPAddress.Loopback, stun.BoundPort!.Value);
        await client.SendToAsync(request, SocketFlags.None, stunEp);

        var buf = new byte[512];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = await client.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);
        var resp = buf.AsSpan(0, received.ReceivedBytes);

        Assert.Equal(32, resp.Length);
        Assert.Equal(0x0101, BinaryPrimitives.ReadUInt16BigEndian(resp[..2]));
        Assert.Equal(12, BinaryPrimitives.ReadUInt16BigEndian(resp.Slice(2, 2)));
        Assert.Equal(StunServer.MagicCookie, BinaryPrimitives.ReadUInt32BigEndian(resp.Slice(4, 4)));
        Assert.True(resp.Slice(8, 12).SequenceEqual(txId));
        Assert.Equal(0x0020, BinaryPrimitives.ReadUInt16BigEndian(resp.Slice(20, 2)));
        Assert.Equal(0x01, resp[25]);

        var mappedPort = BinaryPrimitives.ReadUInt16BigEndian(resp.Slice(26, 2)) ^ (ushort)(StunServer.MagicCookie >> 16);
        var mappedIp = new IPAddress(
        [
            (byte)(resp[28] ^ resp[4]),
            (byte)(resp[29] ^ resp[5]),
            (byte)(resp[30] ^ resp[6]),
            (byte)(resp[31] ^ resp[7]),
        ]);
        Assert.Equal(localEp.Address, mappedIp);
        Assert.Equal(localEp.Port, mappedPort);

        // Non-STUN / malformed packets are ignored (return null).
        Assert.Null(StunServer.TryBuildBindingResponse("not a stun packet"u8, localEp));
        Assert.NotNull(StunServer.TryBuildBindingResponse(request, new IPEndPoint(IPAddress.IPv6Loopback, 45678)));
    }

    [Fact]
    public async Task Devices_endpoint_exposes_v2_features_live_and_clears_when_host_disconnects()
    {
        await using var server = await RelayTestServer.StartAsync(s => s.AccessKey = AccessKey);
        using var host = new TestDevice("Mac Studio", "desktop");
        using var phone = new TestDevice("iPhone", "phone");

        var hostToken = (await server.SignInWithKeyAsync(host, AccessKey)).GetProperty("accessToken").GetString()!;
        var phoneToken = (await server.SignInWithKeyAsync(phone, AccessKey)).GetProperty("accessToken").GetString()!;

        async Task<JsonElement> GetHostRowAsync()
        {
            using var http = server.CreateHttpClient();
            using var req = new HttpRequestMessage(HttpMethod.Get, "/v1/devices");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", phoneToken);
            using var res = await http.SendAsync(req);
            res.EnsureSuccessStatusCode();
            var devices = JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.GetProperty("devices");
            return devices.EnumerateArray().Single(d => d.GetProperty("id").GetString() == host.Id).Clone();
        }

        using (var hostWs = await server.ConnectHostAsync(host, hostToken, features: ["password-access", "protocol-v2", "quic", "p2p"]))
        {
            var row1 = await GetHostRowAsync();
            Assert.True(row1.GetProperty("online").GetBoolean());
            Assert.True(row1.GetProperty("passwordAccess").GetBoolean());
            var f1 = row1.GetProperty("features").EnumerateArray().Select(x => x.GetString()).ToList();
            Assert.Equal(["password-access", "protocol-v2", "quic", "p2p"], f1);

            await RelayTestServer.SendTextAsync(hostWs, """{"type":"features","features":["protocol-v2","p2p"]}""");
            var deadline = Environment.TickCount64 + 3000;
            while (server.Hub.HasFeature(host.Id, "password-access") && Environment.TickCount64 < deadline)
            {
                await Task.Delay(15);
            }

            var row2 = await GetHostRowAsync();
            Assert.False(row2.GetProperty("passwordAccess").GetBoolean());
            var f2 = row2.GetProperty("features").EnumerateArray().Select(x => x.GetString()).ToList();
            Assert.Equal(["protocol-v2", "p2p"], f2);

            await hostWs.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);
        }

        var offlineDeadline = Environment.TickCount64 + 3000;
        while (server.Hub.IsOnline(host.Id) && Environment.TickCount64 < offlineDeadline)
        {
            await Task.Delay(15);
        }

        var row3 = await GetHostRowAsync();
        Assert.False(row3.GetProperty("online").GetBoolean());
        Assert.False(row3.TryGetProperty("features", out _));
    }

    [Fact]
    public async Task Quic_tunnel_forwards_quic_to_quic_and_mixed_quic_to_websocket()
    {
        if (!QuicRelayServer.IsSupported)
        {
            return;
        }

        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()))
        {
            return;
        }

        await RunQuicTunnelTestsCoreAsync();
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private static async Task RunQuicTunnelTestsCoreAsync()
    {
        await using var server = await RelayTestServer.StartAsync(s =>
        {
            s.AccessKey = AccessKey;
            s.QuicBindAddress = IPAddress.Loopback;
            s.QuicPort = 0;
        });

        var quic = server.Services.GetRequiredService<QuicRelayServer>();
        Assert.True(quic.IsRunning);
        var quicPort = quic.BoundPort!.Value;

        using var http = server.CreateHttpClient();
        using var infoRes = await http.GetAsync("/v1/info");
        infoRes.EnsureSuccessStatusCode();
        var info = JsonDocument.Parse(await infoRes.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal($"quic://127.0.0.1:{quicPort}", info.GetProperty("quicEndpoint").GetString());
        Assert.Contains("quic", info.GetProperty("transports").EnumerateArray().Select(x => x.GetString()));

        using var host = new TestDevice("Studio", "desktop");
        using var phone = new TestDevice("Phone", "phone");
        var hostToken = (await server.SignInWithKeyAsync(host, AccessKey)).GetProperty("accessToken").GetString()!;
        var phoneToken = (await server.SignInWithKeyAsync(phone, AccessKey)).GetProperty("accessToken").GetString()!;
        using var hostControl = await server.ConnectHostAsync(host, hostToken, features: ["protocol-v2", "quic"]);

        // 1. QUIC <-> QUIC tunnel
        var tunnel1 = await server.RequestTunnelAsync(phoneToken, host.Id);
        _ = await RelayTestServer.ReceiveTextAsync(hostControl);

        var (hostConn1, hostStream1, hostResp1) = await JoinQuicAsync(quicPort, tunnel1, "host", hostToken);
        Assert.True(hostResp1.GetProperty("ok").GetBoolean());
        await using (hostConn1)
        await using (hostStream1)
        {
            // Invalid token is rejected with unauthorized.
            var (badConn, badStream, badResp) = await JoinQuicAsync(quicPort, tunnel1, "device", "oa1.invalid.token");
            await using (badConn)
            await using (badStream)
            {
                Assert.False(badResp.GetProperty("ok").GetBoolean());
                Assert.Equal("unauthorized", badResp.GetProperty("error").GetString());
            }

            var (devConn1, devStream1, devResp1) = await JoinQuicAsync(quicPort, tunnel1, "device", phoneToken);
            Assert.True(devResp1.GetProperty("ok").GetBoolean());
            await using (devConn1)
            await using (devStream1)
            {
                // Duplicate join returns conflict.
                var (dupConn, dupStream, dupResp) = await JoinQuicAsync(quicPort, tunnel1, "device", phoneToken);
                await using (dupConn)
                await using (dupStream)
                {
                    Assert.False(dupResp.GetProperty("ok").GetBoolean());
                    Assert.Equal("conflict", dupResp.GetProperty("error").GetString());
                }

                var msgToHost = RandomNumberGenerator.GetBytes(64 * 1024);
                await QuicTunnelEnd.WriteFramedAsync(devStream1, msgToHost, CancellationToken.None);
                var gotAtHost = await QuicTunnelEnd.ReadFramedMessageAsync(hostStream1, QuicTunnelEnd.MaxMessageBytes, CancellationToken.None);
                Assert.Equal(msgToHost, gotAtHost);

                var msgToDev = RandomNumberGenerator.GetBytes(16 * 1024);
                await QuicTunnelEnd.WriteFramedAsync(hostStream1, msgToDev, CancellationToken.None);
                var gotAtDev = await QuicTunnelEnd.ReadFramedMessageAsync(devStream1, QuicTunnelEnd.MaxMessageBytes, CancellationToken.None);
                Assert.Equal(msgToDev, gotAtDev);
            }
        }

        // 2. Mixed QUIC (host) <-> WebSocket (device) tunnel
        var tunnel2 = await server.RequestTunnelAsync(phoneToken, host.Id);
        _ = await RelayTestServer.ReceiveTextAsync(hostControl);

        var (hostConn2, hostStream2, hostResp2) = await JoinQuicAsync(quicPort, tunnel2, "host", hostToken);
        Assert.True(hostResp2.GetProperty("ok").GetBoolean());
        await using (hostConn2)
        await using (hostStream2)
        using (var devWs = await server.JoinTunnelAsync(tunnel2, "device", phoneToken))
        {
            // Device sends fragmented WebSocket binary message -> Host receives 1 framed QUIC message.
            var fromWs = RandomNumberGenerator.GetBytes(96 * 1024);
            await devWs.SendAsync(fromWs.AsMemory(0, 40 * 1024), WebSocketMessageType.Binary, endOfMessage: false, CancellationToken.None);
            await devWs.SendAsync(fromWs.AsMemory(40 * 1024), WebSocketMessageType.Binary, endOfMessage: true, CancellationToken.None);

            var receivedAtQuicHost = await QuicTunnelEnd.ReadFramedMessageAsync(hostStream2, QuicTunnelEnd.MaxMessageBytes, CancellationToken.None);
            Assert.Equal(fromWs, receivedAtQuicHost);

            // Host sends framed QUIC message -> Device receives WebSocket binary message.
            var fromQuic = RandomNumberGenerator.GetBytes(48 * 1024);
            await QuicTunnelEnd.WriteFramedAsync(hostStream2, fromQuic, CancellationToken.None);
            var receivedAtWsDev = await RelayTestServer.ReceiveBinaryAsync(devWs);
            Assert.Equal(fromQuic, receivedAtWsDev);
        }
    }

    [Fact]
    public void ServerSettings_parses_stun_and_quic_cli_flags()
    {
        var settings = ServerSettings.Load(
        [
            "--stun-port", "3478",
            "--stun-host", "relay.example.com",
            "--stun-servers", "stun.l.google.com:19302,stun:stun.cloudflare.com:3478",
            "--quic-port", "8443",
            "--quic-host", "quic.example.com",
        ]);

        var (errors, _) = settings.Check();
        Assert.Empty(errors);
        Assert.Equal(3478, settings.StunPort);
        Assert.Equal("relay.example.com", settings.StunHost);
        Assert.Equal(["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"], settings.ExternalStunServers);
        Assert.Equal(8443, settings.QuicPort);
        Assert.Equal("quic.example.com", settings.QuicHost);
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private static async Task<(QuicConnection Connection, QuicStream Stream, JsonElement Response)> JoinQuicAsync(
        int port,
        string tunnelId,
        string role,
        string token)
    {
        var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, port),
            DefaultStreamErrorCode = 0x0A,
            DefaultCloseErrorCode = 0x0B,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ApplicationProtocols = [QuicRelayServer.ApplicationProtocol],
                TargetHost = "localhost",
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            },
        });

        var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        var join = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { tunnel = tunnelId, role, token }));
        await QuicTunnelEnd.WriteFramedAsync(stream, join, CancellationToken.None);
        var replyBytes = await QuicTunnelEnd.ReadFramedMessageAsync(stream, 4096, CancellationToken.None);
        Assert.NotNull(replyBytes);
        var doc = JsonDocument.Parse(replyBytes!).RootElement.Clone();
        return (connection, stream, doc);
    }
}
