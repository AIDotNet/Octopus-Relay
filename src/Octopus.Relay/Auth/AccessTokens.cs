using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Octopus.Relay.Auth;

public readonly record struct AccessGrant(string AccountId, string DeviceId);

/// <summary>Stateless HMAC-signed 15-minute access tokens (<c>oa1.&lt;payload&gt;.&lt;HMAC&gt;</c>).</summary>
public sealed class AccessTokens(byte[] serverSecret, TimeProvider time)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private const string Prefix = "oa1.";
    private const int MaxLength = 1024;

    private readonly ConcurrentDictionary<string, long> _revoked = new(StringComparer.Ordinal);
    private readonly byte[] _key = Secrets.DeriveKey(serverSecret, "access-token");

    public string Issue(string accountId, string deviceId)
    {
        var now = time.GetUtcNow();
        var issued = now.ToUnixTimeMilliseconds();
        if (_revoked.TryGetValue(deviceId, out var revokedAt) && issued <= revokedAt)
        {
            issued = revokedAt + 1;
        }

        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("a", accountId);
            json.WriteString("d", deviceId);
            json.WriteNumber("i", issued);
            json.WriteNumber("e", (now + Lifetime).ToUnixTimeSeconds());
            json.WriteEndObject();
        }

        var payload = Base64Url.EncodeToString(buffer.ToArray());
        return Prefix + payload + "." + Base64Url.EncodeToString(Sign(payload));
    }

    public bool TryValidate(string? token, out AccessGrant grant)
    {
        grant = default;
        if (token is null || token.Length > MaxLength || !token.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var dot = token.IndexOf('.', Prefix.Length);
        if (dot < 0 || token.IndexOf('.', dot + 1) >= 0)
        {
            return false;
        }

        var payload = token[Prefix.Length..dot];
        Span<byte> mac = stackalloc byte[HMACSHA256.HashSizeInBytes + 4];
        if (!Base64Url.TryDecodeFromChars(token.AsSpan(dot + 1), mac, out var macLength)
            || !Secrets.FixedTimeEquals(mac[..macLength], Sign(payload)))
        {
            return false;
        }

        try
        {
            using var json = JsonDocument.Parse(Base64Url.DecodeFromChars(payload));
            var root = json.RootElement;
            var accountId = root.GetProperty("a").GetString();
            var deviceId = root.GetProperty("d").GetString();
            var issued = root.GetProperty("i").GetInt64();
            var expires = root.GetProperty("e").GetInt64();
            if (accountId is null || deviceId is null || expires <= time.GetUtcNow().ToUnixTimeSeconds())
            {
                return false;
            }

            if (_revoked.TryGetValue(deviceId, out var revokedAt) && issued <= revokedAt)
            {
                return false;
            }

            grant = new AccessGrant(accountId, deviceId);
            return true;
        }
        catch (Exception e) when (e is JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
        {
            return false;
        }
    }

    public void Revoke(string deviceId)
    {
        var now = time.GetUtcNow().ToUnixTimeMilliseconds();
        _revoked.AddOrUpdate(deviceId, now, (_, earlier) => Math.Max(earlier + 1, now));

        var stale = now - (long)Lifetime.TotalMilliseconds - 1000;
        foreach (var entry in _revoked)
        {
            if (entry.Value < stale)
            {
                _revoked.TryRemove(entry);
            }
        }
    }

    private byte[] Sign(string payload)
    {
        return HMACSHA256.HashData(_key, Encoding.ASCII.GetBytes(Prefix + payload));
    }
}
