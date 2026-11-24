using System.Text.Json.Serialization;

namespace Octopus.Relay.Storage;

public static class DeviceKinds
{
    public const string Desktop = "desktop";
    public const string Phone = "phone";
}

/// <summary>Single owner profile for this self-hosted relay instance.</summary>
public sealed class OwnerProfile
{
    public string Id { get; set; } = "";

    public string Name { get; set; } = "Owner";

    public string? PasswordHash { get; set; }

    public string? AccessKeyHash { get; set; }

    public string? AccessKeyHint { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>One authorized desktop or mobile device.</summary>
public sealed class DeviceRecord
{
    public string Id { get; set; } = "";

    public string Name { get; set; } = "";

    public string Kind { get; set; } = DeviceKinds.Desktop;

    public string? Platform { get; set; }

    public string? AppVersion { get; set; }

    public string PublicKey { get; set; } = "";

    public string RefreshHash { get; set; } = "";

    public string? PreviousRefreshHash { get; set; }

    public DateTimeOffset? RotatedAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset LastSeenAt { get; set; }

    public string? LastIp { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DeviceRecord Clone() => new()
    {
        Id = Id,
        Name = Name,
        Kind = Kind,
        Platform = Platform,
        AppVersion = AppVersion,
        PublicKey = PublicKey,
        RefreshHash = RefreshHash,
        PreviousRefreshHash = PreviousRefreshHash,
        RotatedAt = RotatedAt,
        CreatedAt = CreatedAt,
        LastSeenAt = LastSeenAt,
        LastIp = LastIp,
        ExpiresAt = ExpiresAt,
    };
}

/// <summary>Browser session for the built-in management UI.</summary>
public sealed class WebSessionRecord
{
    public string TokenHash { get; set; } = "";

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset LastSeenAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public string? UserAgent { get; set; }

    public string? Ip { get; set; }
}

/// <summary>Root JSON document persisted atomically to <c>state.json</c>.</summary>
public sealed class RelayStateDocument
{
    public int Schema { get; set; } = 1;

    public OwnerProfile Owner { get; set; } = new();

    public List<DeviceRecord> Devices { get; set; } = [];

    public List<WebSessionRecord> WebSessions { get; set; } = [];

    public Dictionary<string, long> UsageByMonth { get; set; } = new(StringComparer.Ordinal);
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(RelayStateDocument))]
internal sealed partial class StateJsonContext : JsonSerializerContext;
