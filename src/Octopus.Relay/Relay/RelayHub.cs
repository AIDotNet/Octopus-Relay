using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Octopus.Relay.Api;

namespace Octopus.Relay.Relay;

/// <summary>
/// Manages online hosts and end-to-end encrypted binary tunnels.
/// The hub never inspects application payloads; it only pairs authenticated ends and forwards frames verbatim.
/// </summary>
public sealed class RelayHub(RelayOptions options, IRelayUsage usage)
{
    internal const int UsageFlushBytes = 1024 * 1024;

    private const int ForwardBufferBytes = 64 * 1024;
    private const int ControlBufferBytes = 4096;
    private const int MaxFeatures = 16;
    private const int MaxFeatureLength = 48;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, HostConnection> _hosts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Tunnel> _tunnels = new(StringComparer.Ordinal);

    public int HostCount
    {
        get
        {
            lock (_gate)
            {
                return _hosts.Count;
            }
        }
    }

    public int TunnelCount
    {
        get
        {
            lock (_gate)
            {
                return _tunnels.Count;
            }
        }
    }

    public bool IsOnline(string deviceId)
    {
        lock (_gate)
        {
            return _hosts.ContainsKey(deviceId);
        }
    }

    /// <summary>Whether an online host currently advertises <paramref name="feature"/> (e.g. <c>password-access</c>).</summary>
    public bool HasFeature(string deviceId, string feature)
    {
        HostConnection? host;
        lock (_gate)
        {
            _hosts.TryGetValue(deviceId, out host);
        }

        if (host is null)
        {
            return false;
        }

        foreach (var entry in host.Features)
        {
            if (string.Equals(entry, feature, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public IReadOnlyList<string> FeaturesOf(string deviceId)
    {
        HostConnection? host;
        lock (_gate)
        {
            _hosts.TryGetValue(deviceId, out host);
        }

        return host?.Features ?? [];
    }

    /// <summary>
    /// Runs an authenticated host's control connection until it disconnects or is kicked/replaced.
    /// Accepts live <c>{"type":"features","features":[...]}</c> updates from the host.
    /// </summary>
    public async Task RunHostAsync(
        string accountId,
        string deviceId,
        WebSocket socket,
        IReadOnlyList<string>? initialFeatures,
        CancellationToken cancellationToken)
    {
        var connection = new HostConnection(accountId, deviceId, new RelaySocket(socket), NormalizeFeatures(initialFeatures));
        HostConnection? replaced;
        var refusal = 0;
        lock (_gate)
        {
            _hosts.TryGetValue(deviceId, out replaced);
            var total = _hosts.Count - (replaced is null ? 0 : 1);
            if (total >= options.MaxHosts)
            {
                refusal = RelayCloseCodes.Full;
            }
            else
            {
                _hosts[deviceId] = connection;
            }
        }

        if (refusal != 0)
        {
            await connection.Socket.CloseAsync((WebSocketCloseStatus)refusal, "full", drain: true).ConfigureAwait(false);
            return;
        }

        if (replaced is not null)
        {
            _ = replaced.CloseAsync(RelayCloseCodes.Replaced, "replaced");
        }

        using var aborted = cancellationToken.Register(() => connection.Cancel(TimeSpan.Zero));
        try
        {
            var registered = Encoding.UTF8.GetBytes($$"""{"type":"registered","deviceId":"{{deviceId}}"}""");
            if (!await connection.Socket.SendAsync(registered, WebSocketMessageType.Text, true, connection.Lifetime.Token).ConfigureAwait(false))
            {
                return;
            }

            var buffer = new byte[ControlBufferBytes];
            var length = 0;
            var oversized = false;
            while (true)
            {
                var remaining = oversized ? buffer.AsMemory() : buffer.AsMemory(length);
                var received = await socket.ReceiveAsync(remaining, connection.Lifetime.Token).ConfigureAwait(false);
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                if (received.MessageType != WebSocketMessageType.Text)
                {
                    if (received.EndOfMessage)
                    {
                        length = 0;
                        oversized = false;
                    }

                    continue;
                }

                if (!oversized)
                {
                    length += received.Count;
                    if (length >= ControlBufferBytes && !received.EndOfMessage)
                    {
                        oversized = true;
                        length = 0;
                    }
                }

                if (received.EndOfMessage)
                {
                    if (!oversized && length > 0)
                    {
                        HandleHostMessage(connection, buffer.AsSpan(0, length));
                    }

                    length = 0;
                    oversized = false;
                }
            }

            await connection.Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", drain: false).ConfigureAwait(false);
        }
        catch (Exception e) when (IsConnectionEnd(e))
        {
            connection.Socket.Abort();
        }
        finally
        {
            lock (_gate)
            {
                if (_hosts.TryGetValue(deviceId, out var current) && current == connection)
                {
                    _hosts.Remove(deviceId);
                }
            }
        }
    }

    public async ValueTask<TunnelRequest> RequestTunnelAsync(string accountId, string deviceId, string hostDeviceId, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (!_hosts.TryGetValue(hostDeviceId, out var online) || online.AccountId != accountId)
            {
                return new TunnelRequest(TunnelRequestStatus.HostOffline, null);
            }
        }

        if (options.MonthlyBytesLimit > 0 && await usage.GetAsync(cancellationToken).ConfigureAwait(false) >= options.MonthlyBytesLimit)
        {
            return new TunnelRequest(TunnelRequestStatus.OverQuota, null);
        }

        HostConnection host;
        Tunnel tunnel;
        lock (_gate)
        {
            if (!_hosts.TryGetValue(hostDeviceId, out host!) || host.AccountId != accountId)
            {
                return new TunnelRequest(TunnelRequestStatus.HostOffline, null);
            }

            var ofHost = 0;
            foreach (var existing in _tunnels.Values)
            {
                if (existing.HostDeviceId == hostDeviceId)
                {
                    ofHost++;
                }
            }

            if (_tunnels.Count >= options.MaxTunnels || ofHost >= options.MaxTunnelsPerHost)
            {
                return new TunnelRequest(TunnelRequestStatus.Busy, null);
            }

            tunnel = new Tunnel(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)), accountId, hostDeviceId, deviceId);
            _tunnels[tunnel.Id] = tunnel;
        }

        _ = ExpireUnpairedAsync(tunnel, options.PeerWait * 2);

        var notice = Encoding.UTF8.GetBytes($$"""{"type":"connect","tunnel":"{{tunnel.Id}}"}""");
        var told = false;
        try
        {
            told = await host.Socket.SendAsync(notice, WebSocketMessageType.Text, true, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (IsConnectionEnd(e))
        {
        }

        if (!told)
        {
            await CloseTunnelAsync(tunnel, WebSocketCloseStatus.EndpointUnavailable, "host offline").ConfigureAwait(false);
            return new TunnelRequest(TunnelRequestStatus.HostOffline, null);
        }

        return new TunnelRequest(TunnelRequestStatus.Created, tunnel.Id);
    }

    public TunnelJoinStatus Join(string tunnelId, string accountId, string deviceId, TunnelRole role, out TunnelSeat? seat)
    {
        seat = null;
        lock (_gate)
        {
            if (!_tunnels.TryGetValue(tunnelId, out var tunnel))
            {
                return TunnelJoinStatus.NotFound;
            }

            var expected = role == TunnelRole.Host ? tunnel.HostDeviceId : tunnel.DeviceId;
            if (tunnel.AccountId != accountId || expected != deviceId)
            {
                return TunnelJoinStatus.Forbidden;
            }

            if (role == TunnelRole.Host ? tunnel.HostTaken : tunnel.DeviceTaken)
            {
                return TunnelJoinStatus.Taken;
            }

            if (role == TunnelRole.Host)
            {
                tunnel.HostTaken = true;
            }
            else
            {
                tunnel.DeviceTaken = true;
            }

            seat = new TunnelSeat(tunnel, role);
            return TunnelJoinStatus.Joined;
        }
    }

    public void Abandon(TunnelSeat seat)
    {
        _ = CloseTunnelAsync(seat.Tunnel, WebSocketCloseStatus.EndpointUnavailable, "peer lost");
    }

    public async Task RunTunnelAsync(TunnelSeat seat, WebSocket socket, CancellationToken cancellationToken)
    {
        var tunnel = seat.Tunnel;
        var end = new RelaySocket(socket);
        bool closed;
        bool paired;
        lock (_gate)
        {
            closed = tunnel.Closed;
            if (!closed)
            {
                if (seat.Role == TunnelRole.Host)
                {
                    tunnel.Host = end;
                }
                else
                {
                    tunnel.Device = end;
                }

                tunnel.Paired = tunnel.Host is not null && tunnel.Device is not null;
            }

            paired = tunnel.Paired;
        }

        if (closed)
        {
            await end.CloseAsync(WebSocketCloseStatus.EndpointUnavailable, "tunnel closed", drain: true).ConfigureAwait(false);
            return;
        }

        if (paired)
        {
            _ = ForwardAsync(tunnel);
        }
        else
        {
            _ = ExpireUnpairedAsync(tunnel, options.PeerWait);
        }

        using var aborted = cancellationToken.Register(() => _ = CloseTunnelAsync(tunnel, WebSocketCloseStatus.EndpointUnavailable, "peer lost"));
        await tunnel.Done.Task.ConfigureAwait(false);
    }

    public Task KickAsync(string deviceId)
    {
        HostConnection? host;
        List<Tunnel> tunnels;
        lock (_gate)
        {
            _hosts.Remove(deviceId, out host);
            tunnels = [.. _tunnels.Values.Where(tunnel => tunnel.HostDeviceId == deviceId || tunnel.DeviceId == deviceId)];
        }

        var work = new List<Task>(tunnels.Count + 1);
        if (host is not null)
        {
            work.Add(host.CloseAsync(RelayCloseCodes.SignedOut, "signed out"));
        }

        foreach (var tunnel in tunnels)
        {
            work.Add(CloseTunnelAsync(tunnel, WebSocketCloseStatus.PolicyViolation, "signed out"));
        }

        return Task.WhenAll(work);
    }

    private static void HandleHostMessage(HostConnection connection, ReadOnlySpan<byte> payload)
    {
        try
        {
            var message = JsonSerializer.Deserialize(payload, ApiJson.Default.HostControlMessage);
            if (message is { Type: "features" })
            {
                connection.Features = NormalizeFeatures(message.Features);
            }
        }
        catch (JsonException)
        {
            // Ignore malformed or unknown control messages to stay forward-compatible.
        }
    }

    internal static string[] NormalizeFeatures(IReadOnlyList<string>? raw)
    {
        if (raw is null || raw.Count == 0)
        {
            return [];
        }

        var result = new List<string>(Math.Min(raw.Count, MaxFeatures));
        foreach (var item in raw)
        {
            if (result.Count >= MaxFeatures)
            {
                break;
            }

            var trimmed = item?.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.Length > MaxFeatureLength || trimmed.Any(char.IsControl))
            {
                continue;
            }

            if (!result.Contains(trimmed, StringComparer.Ordinal))
            {
                result.Add(trimmed);
            }
        }

        return [.. result];
    }

    private async Task ExpireUnpairedAsync(Tunnel tunnel, TimeSpan wait)
    {
        try
        {
            await Task.Delay(wait, tunnel.Lifetime.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        bool paired;
        lock (_gate)
        {
            paired = tunnel.Paired;
        }

        if (!paired)
        {
            await CloseTunnelAsync(tunnel, WebSocketCloseStatus.EndpointUnavailable, "peer timeout").ConfigureAwait(false);
        }
    }

    private async Task ForwardAsync(Tunnel tunnel)
    {
        var host = tunnel.Host!;
        var device = tunnel.Device!;
        Volatile.Write(ref tunnel.LastActivity, Environment.TickCount64);
        var toDevice = PumpAsync(tunnel, host, device);
        var toHost = PumpAsync(tunnel, device, host);
        if (options.IdleTimeout > TimeSpan.Zero)
        {
            _ = WatchIdleAsync(tunnel, options.IdleTimeout);
        }

        var first = await Task.WhenAny(toDevice, toHost).ConfigureAwait(false);
        var clean = await first.ConfigureAwait(false);
        await CloseTunnelAsync(tunnel, clean ? WebSocketCloseStatus.NormalClosure : WebSocketCloseStatus.EndpointUnavailable, clean ? "peer closed" : "peer lost").ConfigureAwait(false);
        await Task.WhenAll(toDevice, toHost).ConfigureAwait(false);
        await ReportUsageAsync(tunnel).ConfigureAwait(false);
        tunnel.Lifetime.Cancel();
        tunnel.Done.TrySetResult();
    }

    private async Task<bool> PumpAsync(Tunnel tunnel, RelaySocket from, RelaySocket to)
    {
        var buffer = new byte[ForwardBufferBytes];
        var token = tunnel.Lifetime.Token;
        try
        {
            while (true)
            {
                var received = await from.Socket.ReceiveAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    return true;
                }

                Volatile.Write(ref tunnel.LastActivity, Environment.TickCount64);
                if (!await to.SendAsync(buffer.AsMemory(0, received.Count), received.MessageType, received.EndOfMessage, token).ConfigureAwait(false))
                {
                    return true;
                }

                if (Interlocked.Add(ref tunnel.PendingBytes, received.Count) >= UsageFlushBytes && !await ReportUsageAsync(tunnel).ConfigureAwait(false))
                {
                    await CloseTunnelAsync(tunnel, WebSocketCloseStatus.PolicyViolation, "quota").ConfigureAwait(false);
                }
            }
        }
        catch (Exception)
        {
            return false;
        }
    }

    private async Task<bool> ReportUsageAsync(Tunnel tunnel)
    {
        var bytes = Interlocked.Exchange(ref tunnel.PendingBytes, 0);
        if (bytes == 0)
        {
            return true;
        }

        long total;
        try
        {
            total = await usage.AddAsync(bytes, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return true;
        }

        return options.MonthlyBytesLimit <= 0 || total < options.MonthlyBytesLimit;
    }

    private async Task WatchIdleAsync(Tunnel tunnel, TimeSpan idle)
    {
        var period = TimeSpan.FromMilliseconds(Math.Clamp(idle.TotalMilliseconds / 4, 20, 5000));
        try
        {
            while (true)
            {
                await Task.Delay(period, tunnel.Lifetime.Token).ConfigureAwait(false);
                if (Environment.TickCount64 - Volatile.Read(ref tunnel.LastActivity) >= idle.TotalMilliseconds)
                {
                    await CloseTunnelAsync(tunnel, WebSocketCloseStatus.EndpointUnavailable, "idle").ConfigureAwait(false);
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task CloseTunnelAsync(Tunnel tunnel, WebSocketCloseStatus status, string reason)
    {
        RelaySocket? host;
        RelaySocket? device;
        bool paired;
        lock (_gate)
        {
            if (tunnel.Closed)
            {
                return;
            }

            tunnel.Closed = true;
            _tunnels.Remove(tunnel.Id);
            host = tunnel.Host;
            device = tunnel.Device;
            paired = tunnel.Paired;
        }

        await Task.WhenAll(
            host?.CloseAsync(status, reason, drain: !paired) ?? Task.CompletedTask,
            device?.CloseAsync(status, reason, drain: !paired) ?? Task.CompletedTask).ConfigureAwait(false);

        if (paired)
        {
            try
            {
                tunnel.Lifetime.CancelAfter(RelaySocket.CloseGrace);
            }
            catch (ObjectDisposedException)
            {
            }
        }
        else
        {
            tunnel.Lifetime.Cancel();
            tunnel.Done.TrySetResult();
        }
    }

    private static bool IsConnectionEnd(Exception e)
    {
        return e is OperationCanceledException or WebSocketException or ObjectDisposedException or IOException or InvalidOperationException;
    }
}
