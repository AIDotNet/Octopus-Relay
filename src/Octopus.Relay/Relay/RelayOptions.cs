namespace Octopus.Relay.Relay;

/// <summary>Limits and timeouts for the self-hosted relay hub.</summary>
public sealed class RelayOptions
{
    public int MaxHosts { get; set; } = 32;

    public int MaxTunnels { get; set; } = 128;

    public int MaxTunnelsPerHost { get; set; } = 32;

    /// <summary>Monthly relayed traffic cap in bytes. Zero disables the limit.</summary>
    public long MonthlyBytesLimit { get; set; }

    /// <summary>Closes tunnels with no frames in either direction for this duration. Zero disables idle close.</summary>
    public TimeSpan IdleTimeout { get; set; }

    /// <summary>How long the first side of a tunnel waits for the other side to connect.</summary>
    public TimeSpan PeerWait { get; set; } = TimeSpan.FromSeconds(15);
}

/// <summary>Tracks monthly relayed byte totals.</summary>
public interface IRelayUsage
{
    ValueTask<long> GetAsync(CancellationToken cancellationToken);

    ValueTask<long> AddAsync(long bytes, CancellationToken cancellationToken);
}

/// <summary>WebSocket close codes on the host control connection (/v1/host).</summary>
public static class RelayCloseCodes
{
    public const int BadRegistration = 4401;
    public const int SignedOut = 4403;
    public const int Replaced = 4409;
    public const int Full = 4429;
    public const int AccountFull = 4432;
}

public enum TunnelRole
{
    Host,
    Device,
}

public enum TunnelRequestStatus
{
    Created,
    HostOffline,
    Busy,
    OverQuota,
}

public readonly record struct TunnelRequest(TunnelRequestStatus Status, string? TunnelId);

public enum TunnelJoinStatus
{
    Joined,
    NotFound,
    Forbidden,
    Taken,
}

/// <summary>Reserved end of a tunnel returned by <see cref="RelayHub.Join"/>.</summary>
public sealed class TunnelSeat
{
    internal TunnelSeat(Tunnel tunnel, TunnelRole role)
    {
        Tunnel = tunnel;
        Role = role;
    }

    internal Tunnel Tunnel { get; }

    public TunnelRole Role { get; }
}
