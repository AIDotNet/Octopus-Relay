using Octopus.Relay.Storage;

namespace Octopus.Relay.Auth;

/// <summary>Browser session cookies for the embedded management UI.</summary>
public sealed class WebSessions(JsonStateStore store, TimeProvider time)
{
    public const string CookieName = "or_session";

    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(30);
    private static readonly TimeSpan TouchInterval = TimeSpan.FromHours(1);

    public string Create(string? userAgent, string? ip)
    {
        var token = Secrets.RandomToken(32);
        var now = time.GetUtcNow();
        store.AddWebSession(new WebSessionRecord
        {
            TokenHash = Secrets.Sha256Hex(token),
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = now + Lifetime,
            UserAgent = Trim(userAgent, 256),
            Ip = ip,
        });
        return token;
    }

    public OwnerProfile? Authenticate(string? cookie)
    {
        if (string.IsNullOrEmpty(cookie) || cookie.Length > 128)
        {
            return null;
        }

        var hash = Secrets.Sha256Hex(cookie);
        var session = store.GetWebSession(hash);
        if (session is null)
        {
            return null;
        }

        var now = time.GetUtcNow();
        if (now - session.LastSeenAt >= TouchInterval)
        {
            store.TouchWebSession(hash, now, now + Lifetime);
        }

        return store.GetOwner();
    }

    public void Delete(string? cookie)
    {
        if (string.IsNullOrEmpty(cookie) || cookie.Length > 128)
        {
            return;
        }

        store.DeleteWebSession(Secrets.Sha256Hex(cookie));
    }

    private static string? Trim(string? value, int max)
    {
        var text = value?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return null;
        }

        return text.Length > max ? text[..max] : text;
    }
}
