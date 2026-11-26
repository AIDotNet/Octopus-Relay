using Octopus.Relay.Storage;

namespace Octopus.Relay.Auth;

public sealed record TokenGrant(string AccessToken, string RefreshToken, int ExpiresIn, string DeviceId, OwnerProfile Owner);

/// <summary>Notified whenever a device is revoked or signed out so active relay sockets are closed immediately.</summary>
public interface IDeviceSignOut
{
    void SignedOut(string deviceId);
}

/// <summary>Manages authorized devices and single-use rotating refresh tokens (<c>or1.&lt;deviceId&gt;.&lt;random&gt;</c>).</summary>
public sealed class DeviceSessions(JsonStateStore store, AccessTokens tokens, IDeviceSignOut signOut, TimeProvider time, int maxDevices)
{
    /// <summary>
    /// A refresh token not used for this long stops counting; every refresh moves it on. Devices signed in under the
    /// earlier 60 days keep that expiry until their next refresh.
    /// </summary>
    public static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(30);
    public static readonly TimeSpan ReuseGrace = TimeSpan.FromMinutes(2);

    private const string Prefix = "or1.";

    public int MaxDevices => maxDevices;

    public (RegisterDeviceStatus Status, TokenGrant? Grant) SignIn(
        DeviceKey key, string name, string kind, string? platform, string? appVersion, string? ip)
    {
        var owner = store.GetOwner();
        var now = time.GetUtcNow();
        var refresh = NewRefreshToken(key.Id);
        var device = new DeviceRecord
        {
            Id = key.Id,
            Name = name,
            Kind = kind,
            Platform = platform,
            AppVersion = appVersion,
            PublicKey = Convert.ToBase64String(key.Bytes),
            RefreshHash = Secrets.Sha256Hex(refresh),
            CreatedAt = now,
            LastSeenAt = now,
            LastIp = ip,
            ExpiresAt = now + RefreshLifetime,
        };

        var status = store.RegisterDevice(device, maxDevices);
        if (status == RegisterDeviceStatus.LimitReached)
        {
            return (status, null);
        }

        return (status, new TokenGrant(tokens.Issue(owner.Id, key.Id), refresh, (int)AccessTokens.Lifetime.TotalSeconds, key.Id, owner));
    }

    public TokenGrant? Refresh(string? refreshToken, string? ip)
    {
        if (!TryParse(refreshToken, out var deviceId))
        {
            return null;
        }

        var presented = Secrets.Sha256Hex(refreshToken!);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var device = store.GetDevice(deviceId);
            if (device is null)
            {
                return null;
            }

            var now = time.GetUtcNow();
            bool isCurrent;
            if (Secrets.FixedTimeEqualsString(device.RefreshHash, presented))
            {
                isCurrent = true;
            }
            else if (device.PreviousRefreshHash is not null && Secrets.FixedTimeEqualsString(device.PreviousRefreshHash, presented))
            {
                if (device.RotatedAt is not { } rotatedAt || now - rotatedAt >= ReuseGrace)
                {
                    if (store.DeleteDevice(deviceId))
                    {
                        Kick(deviceId);
                    }

                    return null;
                }

                isCurrent = false;
            }
            else
            {
                return null;
            }

            var owner = store.GetOwner();
            var nextRefresh = NewRefreshToken(deviceId);
            if (store.RotateRefresh(deviceId, presented, isCurrent, Secrets.Sha256Hex(nextRefresh), now, now + RefreshLifetime, ip))
            {
                return new TokenGrant(tokens.Issue(owner.Id, deviceId), nextRefresh, (int)AccessTokens.Lifetime.TotalSeconds, deviceId, owner);
            }
        }

        return null;
    }

    public void Revoke(string? refreshToken)
    {
        if (!TryParse(refreshToken, out var deviceId))
        {
            return;
        }

        var device = store.GetDevice(deviceId);
        if (device is not null
            && Secrets.FixedTimeEqualsString(device.RefreshHash, Secrets.Sha256Hex(refreshToken!))
            && store.DeleteDevice(deviceId))
        {
            Kick(deviceId);
        }
    }

    public bool Remove(string deviceId)
    {
        if (!store.DeleteDevice(deviceId))
        {
            return false;
        }

        Kick(deviceId);
        return true;
    }

    public void SignOutEverywhere()
    {
        foreach (var deviceId in store.DeleteAllDevices())
        {
            Kick(deviceId);
        }

        store.DeleteAllWebSessions();
    }

    private void Kick(string deviceId)
    {
        tokens.Revoke(deviceId);
        signOut.SignedOut(deviceId);
    }

    private static string NewRefreshToken(string deviceId)
    {
        return Prefix + deviceId + "." + Secrets.RandomToken(32);
    }

    private static bool TryParse(string? token, out string deviceId)
    {
        deviceId = "";
        if (token is null || token.Length > 128 || !token.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var dot = token.IndexOf('.', Prefix.Length);
        if (dot < 0 || dot == token.Length - 1)
        {
            return false;
        }

        deviceId = token[Prefix.Length..dot];
        return DeviceKey.IsDeviceId(deviceId);
    }
}
