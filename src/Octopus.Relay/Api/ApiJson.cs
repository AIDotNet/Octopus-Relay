using System.Text.Json.Serialization;

namespace Octopus.Relay.Api;

internal sealed record ErrorBody(string Error)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RetryAfter { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MaxDevices { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<WebDeviceBody>? Devices { get; init; }
}

// ---- /v1/* client & relay protocol ----

internal sealed record RelayInfoBody(int Protocol, string Mode, string Name, string Version, IReadOnlyList<string> Auth)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Transports { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? StunServers { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? QuicEndpoint { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? IdleTimeoutSeconds { get; init; }
}

internal sealed record DeviceStartRequest(string? DeviceName, string? Kind, string? PublicKey, string? Platform, string? AppVersion);

internal sealed record DeviceStartBody(string DeviceCode, string UserCode, string VerificationUri, string VerificationUriComplete, int ExpiresIn, int Interval);

internal sealed record KeyChallengeBody(string Challenge, int ExpiresIn);

internal sealed record KeyLoginRequest(
    string? AccessKey,
    string? Challenge,
    string? DeviceName,
    string? Kind,
    string? PublicKey,
    string? Signature,
    string? Platform,
    string? AppVersion);

internal sealed record TokenRequest(string? GrantType, string? DeviceCode, string? Signature, string? RefreshToken);

internal sealed record ClientAccountBody(string Id, string Name, string Email);

internal sealed record TokenBody(string AccessToken, string RefreshToken, int ExpiresIn, string DeviceId, ClientAccountBody Account);

internal sealed record RevokeRequest(string? RefreshToken);

internal sealed record ClientDeviceBody(
    string Id,
    string Name,
    string Kind,
    string? Platform,
    string? AppVersion,
    bool Online,
    bool Current,
    bool PasswordAccess,
    DateTime CreatedAt,
    DateTime LastSeenAt)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Features { get; init; }
}

internal sealed record ClientDevicesBody(IReadOnlyList<ClientDeviceBody> Devices);

internal sealed record TunnelRequestBody(string? HostDeviceId);

internal sealed record TunnelBody(string Tunnel);

internal sealed record ChallengeMessage(string Type, string Nonce);

internal sealed record RegisterMessage(string? Type, string? PublicKey, string? Name, string? Signature, List<string>? Features);

internal sealed record HostControlMessage(string? Type, List<string>? Features);

internal sealed record QuicTunnelJoinRequest(string? Tunnel, string? Role, string? Token);

internal sealed record QuicTunnelJoinResponse(
    bool Ok,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Error = null);

// ---- /api/* built-in management UI ----

internal sealed record WebStatusBody(
    string ServerName,
    string Version,
    bool NeedsSetup,
    bool PasswordEnabled,
    bool PasswordManagedByEnv,
    bool AccessKeyEnabled,
    bool AccessKeyManagedByEnv,
    bool SignedIn);

internal sealed record SetupRequest(string? SetupToken, string? OwnerName, string? Password, bool GenerateAccessKey);

internal sealed record SetupResponseBody(
    WebAccountBody Account,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AccessKey,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SetupLink);

internal sealed record PasswordLoginRequest(string? Password);

internal sealed record NameRequest(string? Name);

internal sealed record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);

internal sealed record CodeRequest(string? Code);

internal sealed record WebAccountBody(string Id, string Name, DateTime CreatedAt);

internal sealed record WebStatsBody(int OnlineHosts, int ActiveTunnels, long MonthlyBytes, long MonthlyLimitBytes, DateTime StartedAt)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? StunEndpoint { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? QuicEndpoint { get; init; }
}

internal sealed record WebDashboardBody(
    string ServerName,
    string Version,
    string PublicUrl,
    WebAccountBody Account,
    WebStatsBody Stats,
    int MaxDevices,
    int DeviceCount,
    bool PasswordEnabled,
    bool PasswordManagedByEnv,
    bool AccessKeyEnabled,
    bool AccessKeyManagedByEnv,
    string? AccessKeyHint,
    IReadOnlyList<WebDeviceBody> Devices);

internal sealed record WebDeviceBody(
    string Id,
    string Name,
    string Kind,
    string? Platform,
    string? AppVersion,
    bool Online,
    bool PasswordAccess,
    DateTime CreatedAt,
    DateTime LastSeenAt,
    string? LastIp)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Features { get; init; }
}

internal sealed record DeviceLoginBody(
    string UserCode,
    string DeviceId,
    string DeviceName,
    string Kind,
    string? Platform,
    string? AppVersion,
    string? Ip,
    DateTime RequestedAt,
    bool Known);

internal sealed record AccessKeyRotateBody(string AccessKey, string Hint, string SetupLink);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ErrorBody))]
[JsonSerializable(typeof(RelayInfoBody))]
[JsonSerializable(typeof(DeviceStartRequest))]
[JsonSerializable(typeof(DeviceStartBody))]
[JsonSerializable(typeof(KeyChallengeBody))]
[JsonSerializable(typeof(KeyLoginRequest))]
[JsonSerializable(typeof(TokenRequest))]
[JsonSerializable(typeof(ClientAccountBody))]
[JsonSerializable(typeof(TokenBody))]
[JsonSerializable(typeof(RevokeRequest))]
[JsonSerializable(typeof(ClientDevicesBody))]
[JsonSerializable(typeof(TunnelRequestBody))]
[JsonSerializable(typeof(TunnelBody))]
[JsonSerializable(typeof(ChallengeMessage))]
[JsonSerializable(typeof(RegisterMessage))]
[JsonSerializable(typeof(HostControlMessage))]
[JsonSerializable(typeof(QuicTunnelJoinRequest))]
[JsonSerializable(typeof(QuicTunnelJoinResponse))]
[JsonSerializable(typeof(WebStatusBody))]
[JsonSerializable(typeof(SetupRequest))]
[JsonSerializable(typeof(SetupResponseBody))]
[JsonSerializable(typeof(PasswordLoginRequest))]
[JsonSerializable(typeof(NameRequest))]
[JsonSerializable(typeof(ChangePasswordRequest))]
[JsonSerializable(typeof(CodeRequest))]
[JsonSerializable(typeof(WebAccountBody))]
[JsonSerializable(typeof(WebDashboardBody))]
[JsonSerializable(typeof(DeviceLoginBody))]
[JsonSerializable(typeof(AccessKeyRotateBody))]
internal sealed partial class ApiJson : JsonSerializerContext;
