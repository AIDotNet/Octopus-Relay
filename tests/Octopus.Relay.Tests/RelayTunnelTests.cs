using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using Octopus.Relay.Relay;
using Xunit;

namespace Octopus.Relay.Tests;

public sealed class RelayTunnelTests
{
    private const string AccessKey = "ork_tunnel_test_key_0123456789abcdef";

    [Fact]
    public async Task Host_features_and_passwordAccess_update_live_in_device_list()
    {
        await using var server = await RelayTestServer.StartAsync(s => s.AccessKey = AccessKey);
        using var host = new TestDevice("Studio", "desktop");
        using var phone = new TestDevice("Phone", "phone");

        var hostToken = (await server.SignInWithKeyAsync(host, AccessKey)).GetProperty("accessToken").GetString()!;
        var phoneToken = (await server.SignInWithKeyAsync(phone, AccessKey)).GetProperty("accessToken").GetString()!;

        using var hostWs = await server.ConnectHostAsync(host, hostToken, features: ["password-access"]);
        Assert.True(server.Hub.IsOnline(host.Id));

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

        var row1 = await GetHostRowAsync();
        Assert.True(row1.GetProperty("online").GetBoolean());
        Assert.True(row1.GetProperty("passwordAccess").GetBoolean());
        Assert.Equal("macOS", row1.GetProperty("platform").GetString());

        // Host turns password access off live over the control socket.
        await RelayTestServer.SendTextAsync(hostWs, """{"type":"features","features":[]}""");
        var deadline = Environment.TickCount64 + 3000;
        while (server.Hub.HasFeature(host.Id, "password-access") && Environment.TickCount64 < deadline)
        {
            await Task.Delay(15);
        }

        var row2 = await GetHostRowAsync();
        Assert.True(row2.GetProperty("online").GetBoolean());
        Assert.False(row2.GetProperty("passwordAccess").GetBoolean());
    }

    [Fact]
    public async Task Tunnel_forwards_large_binary_frames_propagates_close_and_kicks_on_device_removal()
    {
        await using var server = await RelayTestServer.StartAsync(s => s.AccessKey = AccessKey);
        using var host = new TestDevice("Studio", "desktop");
        using var laptop = new TestDevice("Laptop", "desktop");

        var hostToken = (await server.SignInWithKeyAsync(host, AccessKey)).GetProperty("accessToken").GetString()!;
        var laptopToken = (await server.SignInWithKeyAsync(laptop, AccessKey)).GetProperty("accessToken").GetString()!;

        using var hostControl = await server.ConnectHostAsync(host, hostToken);
        var tunnelId = await server.RequestTunnelAsync(laptopToken, host.Id);

        // Host receives connect notice on its standing control connection.
        var notice = JsonDocument.Parse(await RelayTestServer.ReceiveTextAsync(hostControl)).RootElement;
        Assert.Equal("connect", notice.GetProperty("type").GetString());
        Assert.Equal(tunnelId, notice.GetProperty("tunnel").GetString());

        using var hostEnd = await server.JoinTunnelAsync(tunnelId, "host", hostToken);
        using var deviceEnd = await server.JoinTunnelAsync(tunnelId, "device", laptopToken);

        // Duplicate join of an already-taken role is rejected with 409 Conflict.
        var duplicate = await Assert.ThrowsAsync<WebSocketException>(() => server.JoinTunnelAsync(tunnelId, "device", laptopToken));
        Assert.Contains("409", duplicate.Message);

        // Forward a 1 MiB binary message split across multiple WebSocket fragments.
        var payload = RandomNumberGenerator.GetBytes(1024 * 1024);
        var sendTask = Task.Run(async () =>
        {
            const int chunk = 256 * 1024;
            for (var offset = 0; offset < payload.Length; offset += chunk)
            {
                var len = Math.Min(chunk, payload.Length - offset);
                var end = offset + len == payload.Length;
                await deviceEnd.SendAsync(payload.AsMemory(offset, len), WebSocketMessageType.Binary, end, CancellationToken.None);
            }
        });
        var received = await RelayTestServer.ReceiveBinaryAsync(hostEnd);
        await sendTask;
        Assert.Equal(payload, received);

        // Echo back from host -> device.
        var reply = RandomNumberGenerator.GetBytes(8192);
        await hostEnd.SendAsync(reply, WebSocketMessageType.Binary, true, CancellationToken.None);
        Assert.Equal(reply, await RelayTestServer.ReceiveBinaryAsync(deviceEnd));

        // Removing the host device immediately kicks its control socket (4403) and closes the tunnel.
        using var http = server.CreateHttpClient();
        using var delReq = new HttpRequestMessage(HttpMethod.Delete, $"/v1/devices/{host.Id}");
        delReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", laptopToken);
        using var delRes = await http.SendAsync(delReq);
        Assert.Equal(HttpStatusCode.NoContent, delRes.StatusCode);

        var controlClosed = await ReceiveCloseAsync(hostControl);
        Assert.Equal((WebSocketCloseStatus)RelayCloseCodes.SignedOut, controlClosed);

        var deviceTunnelClosed = await ReceiveCloseAsync(deviceEnd);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, deviceTunnelClosed);
        Assert.Equal(0, server.Hub.HostCount);
        Assert.Equal(0, server.Hub.TunnelCount);
    }

    [Fact]
    public async Task Replacing_a_host_closes_the_old_control_connection_with_4409_and_enforces_idle_timeout()
    {
        await using var server = await RelayTestServer.StartAsync(s =>
        {
            s.AccessKey = AccessKey;
            s.Relay.IdleTimeout = TimeSpan.FromMilliseconds(250);
        });
        using var host = new TestDevice("Studio");
        using var laptop = new TestDevice("Laptop");

        var hostToken = (await server.SignInWithKeyAsync(host, AccessKey)).GetProperty("accessToken").GetString()!;
        var laptopToken = (await server.SignInWithKeyAsync(laptop, AccessKey)).GetProperty("accessToken").GetString()!;

        using var firstControl = await server.ConnectHostAsync(host, hostToken);
        using var secondControl = await server.ConnectHostAsync(host, hostToken);
        Assert.Equal((WebSocketCloseStatus)RelayCloseCodes.Replaced, await ReceiveCloseAsync(firstControl));

        // Idle tunnel closes automatically after IdleTimeout.
        var tunnelId = await server.RequestTunnelAsync(laptopToken, host.Id);
        _ = await RelayTestServer.ReceiveTextAsync(secondControl);
        using var hostEnd = await server.JoinTunnelAsync(tunnelId, "host", hostToken);
        using var deviceEnd = await server.JoinTunnelAsync(tunnelId, "device", laptopToken);

        Assert.Equal(WebSocketCloseStatus.EndpointUnavailable, await ReceiveCloseAsync(deviceEnd));
    }

    private static async Task<WebSocketCloseStatus?> ReceiveCloseAsync(ClientWebSocket ws)
    {
        var buf = new byte[1024];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while (true)
            {
                var r = await ws.ReceiveAsync(buf, cts.Token);
                if (r.MessageType == WebSocketMessageType.Close)
                {
                    return r.CloseStatus;
                }
            }
        }
        catch (WebSocketException)
        {
            return ws.CloseStatus;
        }
    }
}
