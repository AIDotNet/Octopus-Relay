using System.Security.Cryptography;

namespace Octopus.Relay.Auth;

/// <summary>Single-use 32-byte challenges for browser-free Access Key sign-in (<c>/v1/auth/key</c>).</summary>
public sealed class AccessKeyLogins(TimeProvider time)
{
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);
    public const int ChallengeByteLength = 32;
    public const int MaxPending = 4096;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _challenges = new(StringComparer.Ordinal);

    /// <summary>Issues a fresh single-use base64 challenge, or null if too many are pending.</summary>
    public (string Challenge, int ExpiresIn)? Issue()
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_challenges.Count >= MaxPending)
            {
                Sweep(now);
                if (_challenges.Count >= MaxPending)
                {
                    return null;
                }
            }

            var bytes = RandomNumberGenerator.GetBytes(ChallengeByteLength);
            var encoded = Convert.ToBase64String(bytes);
            _challenges[encoded] = now + ChallengeLifetime;
            return (encoded, (int)ChallengeLifetime.TotalSeconds);
        }
    }

    /// <summary>Atomically consumes <paramref name="encoded"/> and returns its 32 raw bytes, or null if unknown/expired.</summary>
    public byte[]? Consume(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded) || encoded.Length > 64)
        {
            return null;
        }

        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (!_challenges.Remove(encoded, out var expiresAt) || expiresAt <= now)
            {
                return null;
            }
        }

        Span<byte> decoded = stackalloc byte[ChallengeByteLength + 4];
        if (!Convert.TryFromBase64String(encoded, decoded, out var length) || length != ChallengeByteLength)
        {
            return null;
        }

        return decoded[..ChallengeByteLength].ToArray();
    }

    private void Sweep(DateTimeOffset now)
    {
        foreach (var entry in _challenges.Where(e => e.Value <= now).Select(e => e.Key).ToList())
        {
            _challenges.Remove(entry);
        }
    }
}
