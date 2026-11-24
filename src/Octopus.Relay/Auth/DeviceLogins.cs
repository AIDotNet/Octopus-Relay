using System.Security.Cryptography;
using Octopus.Relay.Storage;

namespace Octopus.Relay.Auth;

public sealed record DeviceLoginStart(string DeviceCode, string UserCode, int ExpiresIn, int Interval);

public sealed record PendingDeviceLogin(string UserCode, string DeviceId, string DeviceName, string Kind, string? Platform, string? AppVersion, string? Ip, DateTimeOffset RequestedAt);

public enum ApproveStatus
{
    Approved,
    UnknownCode,
    DeviceLimit,
}

public sealed record ApproveResult(ApproveStatus Status, int MaxDevices = 0, IReadOnlyList<DeviceRecord>? Devices = null);

public enum RedeemStatus
{
    Granted,
    ExpiredToken,
    InvalidGrant,
    AccessDenied,
    SlowDown,
    AuthorizationPending,
}

public sealed record RedeemResult(RedeemStatus Status, TokenGrant? Grant = null);

/// <summary>Device-code browser confirmation flow (<c>/v1/auth/device</c> + <c>/device</c>).</summary>
public sealed class DeviceLogins(JsonStateStore store, DeviceSessions sessions, TimeProvider time, int pollIntervalSeconds = 2)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    public const int MaxPending = 1024;

    private const string UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";

    private readonly Lock _gate = new();
    private readonly Dictionary<string, Entry> _byDeviceCode = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Entry> _byUserCode = new(StringComparer.Ordinal);

    public DeviceLoginStart? Start(DeviceKey key, string deviceName, string kind, string? platform, string? appVersion, string? ip)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_byDeviceCode.Count >= MaxPending)
            {
                Sweep(now);
                if (_byDeviceCode.Count >= MaxPending)
                {
                    return null;
                }
            }

            string userCode;
            do
            {
                userCode = RandomNumberGenerator.GetString(UserCodeAlphabet, 8);
            }
            while (_byUserCode.ContainsKey(userCode));

            var entry = new Entry
            {
                DeviceCode = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)),
                UserCode = userCode,
                Key = key,
                DeviceName = deviceName,
                Kind = kind,
                Platform = platform,
                AppVersion = appVersion,
                Ip = ip,
                RequestedAt = now,
                ExpiresAt = now + Lifetime,
            };
            _byDeviceCode[entry.DeviceCode] = entry;
            _byUserCode[userCode] = entry;
            return new DeviceLoginStart(entry.DeviceCode, Display(userCode), (int)Lifetime.TotalSeconds, pollIntervalSeconds);
        }
    }

    public PendingDeviceLogin? Find(string? userCode)
    {
        lock (_gate)
        {
            var entry = Waiting(userCode);
            return entry is null
                ? null
                : new PendingDeviceLogin(Display(entry.UserCode), entry.Key.Id, entry.DeviceName, entry.Kind, entry.Platform, entry.AppVersion, entry.Ip, entry.RequestedAt);
        }
    }

    public ApproveResult Approve(string? userCode)
    {
        var pending = Find(userCode);
        if (pending is null)
        {
            return new ApproveResult(ApproveStatus.UnknownCode);
        }

        var devices = store.GetDevices();
        var max = sessions.MaxDevices;
        if (max > 0 && devices.All(d => d.Id != pending.DeviceId) && devices.Count >= max)
        {
            return new ApproveResult(ApproveStatus.DeviceLimit, max, devices);
        }

        lock (_gate)
        {
            var entry = Waiting(userCode);
            if (entry is null)
            {
                return new ApproveResult(ApproveStatus.UnknownCode);
            }

            entry.Approved = true;
            return new ApproveResult(ApproveStatus.Approved);
        }
    }

    public bool Deny(string? userCode)
    {
        lock (_gate)
        {
            var entry = Waiting(userCode);
            if (entry is null)
            {
                return false;
            }

            entry.Denied = true;
            return true;
        }
    }

    public RedeemResult Redeem(string? deviceCode, string? signature, string? ip)
    {
        Entry? entry;
        lock (_gate)
        {
            entry = Live(deviceCode);
        }

        if (entry is null)
        {
            return new RedeemResult(RedeemStatus.ExpiredToken);
        }

        Span<byte> signed = stackalloc byte[DeviceKey.SignatureLength];
        if (signature is null || signature.Length > 128
            || !Convert.TryFromBase64String(signature, signed, out var length) || length != DeviceKey.SignatureLength
            || !entry.Key.Verify(DeviceKey.LoginHash(entry.DeviceCode), signed))
        {
            return new RedeemResult(RedeemStatus.InvalidGrant);
        }

        lock (_gate)
        {
            if (Live(deviceCode) != entry)
            {
                return new RedeemResult(RedeemStatus.ExpiredToken);
            }

            if (entry.Denied)
            {
                Remove(entry);
                return new RedeemResult(RedeemStatus.AccessDenied);
            }

            if (!entry.Approved || entry.Redeeming)
            {
                var now = time.GetUtcNow();
                var tooSoon = entry.LastPoll is { } last && (now - last).TotalSeconds < pollIntervalSeconds / 2.0;
                entry.LastPoll = now;
                return new RedeemResult(tooSoon ? RedeemStatus.SlowDown : RedeemStatus.AuthorizationPending);
            }

            entry.Redeeming = true;
        }

        var (_, grant) = sessions.SignIn(entry.Key, entry.DeviceName, entry.Kind, entry.Platform, entry.AppVersion, ip);
        lock (_gate)
        {
            Remove(entry);
        }

        return grant is null ? new RedeemResult(RedeemStatus.AccessDenied) : new RedeemResult(RedeemStatus.Granted, grant);
    }

    public static string? Normalize(string? userCode)
    {
        if (userCode is null || userCode.Length > 32)
        {
            return null;
        }

        Span<char> letters = stackalloc char[8];
        var count = 0;
        foreach (var c in userCode)
        {
            if (c is '-' or ' ')
            {
                continue;
            }

            var upper = char.ToUpperInvariant(c);
            if (count == letters.Length || !UserCodeAlphabet.Contains(upper))
            {
                return null;
            }

            letters[count++] = upper;
        }

        return count == letters.Length ? new string(letters) : null;
    }

    private static string Display(string userCode) => userCode[..4] + "-" + userCode[4..];

    private Entry? Live(string? deviceCode)
    {
        if (deviceCode is null || !_byDeviceCode.TryGetValue(deviceCode, out var entry))
        {
            return null;
        }

        if (entry.ExpiresAt <= time.GetUtcNow())
        {
            Remove(entry);
            return null;
        }

        return entry;
    }

    private Entry? Waiting(string? userCode)
    {
        var code = Normalize(userCode);
        if (code is null || !_byUserCode.TryGetValue(code, out var entry))
        {
            return null;
        }

        if (entry.ExpiresAt <= time.GetUtcNow())
        {
            Remove(entry);
            return null;
        }

        return entry.Denied || entry.Approved ? null : entry;
    }

    private void Remove(Entry entry)
    {
        _byDeviceCode.Remove(entry.DeviceCode);
        _byUserCode.Remove(entry.UserCode);
    }

    private void Sweep(DateTimeOffset now)
    {
        foreach (var entry in _byDeviceCode.Values.Where(e => e.ExpiresAt <= now).ToList())
        {
            Remove(entry);
        }
    }

    private sealed class Entry
    {
        public required string DeviceCode { get; init; }
        public required string UserCode { get; init; }
        public required DeviceKey Key { get; init; }
        public required string DeviceName { get; init; }
        public required string Kind { get; init; }
        public string? Platform { get; init; }
        public string? AppVersion { get; init; }
        public string? Ip { get; init; }
        public DateTimeOffset RequestedAt { get; init; }
        public DateTimeOffset ExpiresAt { get; init; }
        public bool Approved { get; set; }
        public bool Denied { get; set; }
        public bool Redeeming { get; set; }
        public DateTimeOffset? LastPoll { get; set; }
    }
}
