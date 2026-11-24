using System.Security.Cryptography;
using Octopus.Relay.Auth;
using Octopus.Relay.Storage;
using Xunit;

namespace Octopus.Relay.Tests;

public sealed class CryptoAndStoreTests
{
    [Fact]
    public void DeviceKey_derives_the_shared_octopus_test_vector_and_rejects_off_curve_points()
    {
        byte[] vector = [0x04, .. Enumerable.Range(1, 64).Select(i => (byte)i)];
        Assert.Equal("b3j2nk4vp73plguwgcshhuy2pu", DeviceKey.DeriveId(vector));
        Assert.True(DeviceKey.IsDeviceId("b3j2nk4vp73plguwgcshhuy2pu"));
        Assert.False(DeviceKey.IsDeviceId("short"));
        Assert.False(DeviceKey.TryParse(vector, out _));

        using var dev = new TestDevice();
        Assert.True(DeviceKey.TryParse(dev.PublicKeyBase64, out var parsed));
        Assert.Equal(dev.Id, parsed.Id);

        var hash = DeviceKey.KeyLoginHash(RandomNumberGenerator.GetBytes(32));
        var sig = Convert.FromBase64String(dev.SignBase64(hash));
        Assert.True(parsed.Verify(hash, sig));
        sig[0] ^= 0xFF;
        Assert.False(parsed.Verify(hash, sig));
    }

    [Fact]
    public void Password_hashing_verifies_valid_and_rejects_invalid_passwords()
    {
        var encoded = Secrets.HashPassword("correct-horse-battery");
        Assert.StartsWith("pbkdf2-sha256$", encoded);
        Assert.True(Secrets.VerifyPassword("correct-horse-battery", encoded));
        Assert.False(Secrets.VerifyPassword("wrong-password", encoded));
        Assert.False(Secrets.VerifyPassword("correct-horse-battery", "not-a-hash"));
    }

    [Fact]
    public void AccessTokens_issue_validate_expire_and_revoke()
    {
        var clock = new FakeClock(new DateTimeOffset(2026, 11, 25, 0, 0, 0, TimeSpan.Zero));
        var tokens = new AccessTokens(RandomNumberGenerator.GetBytes(48), clock);

        var token = tokens.Issue("acc123", "b3j2nk4vp73plguwgcshhuy2pu");
        Assert.StartsWith("oa1.", token);
        Assert.True(tokens.TryValidate(token, out var grant));
        Assert.Equal(("acc123", "b3j2nk4vp73plguwgcshhuy2pu"), (grant.AccountId, grant.DeviceId));

        tokens.Revoke("b3j2nk4vp73plguwgcshhuy2pu");
        Assert.False(tokens.TryValidate(token, out _));

        var fresh = tokens.Issue("acc123", "b3j2nk4vp73plguwgcshhuy2pu");
        Assert.True(tokens.TryValidate(fresh, out _));

        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.False(tokens.TryValidate(fresh, out _));
    }

    [Fact]
    public void JsonStateStore_persists_atomically_across_reloads_and_detects_refresh_reuse()
    {
        var temp = Directory.CreateTempSubdirectory("octopus-relay-store-").FullName;
        try
        {
            var clock = new FakeClock(new DateTimeOffset(2026, 11, 25, 0, 0, 0, TimeSpan.Zero));
            var secret1 = JsonStateStore.LoadOrCreateSecret(temp);
            var secret2 = JsonStateStore.LoadOrCreateSecret(temp);
            Assert.Equal(secret1, secret2);

            var kicked = new List<string>();
            var signOut = new RecordingSignOut(kicked);

            string ownerId;
            string firstRefresh;
            string secondRefresh;
            using var dev = new TestDevice("MacBook");
            Assert.True(DeviceKey.TryParse(dev.PublicKeyBase64, out var key));

            using (var store = new JsonStateStore(temp, clock, "Alice"))
            {
                ownerId = store.GetOwner().Id;
                var tokens = new AccessTokens(secret1, clock);
                var sessions = new DeviceSessions(store, tokens, signOut, clock, maxDevices: 2);

                var (status, grant1) = sessions.SignIn(key, dev.Name, dev.Kind, "macOS", "1.0.0", "127.0.0.1");
                Assert.Equal(RegisterDeviceStatus.Added, status);
                Assert.NotNull(grant1);
                firstRefresh = grant1!.RefreshToken;

                var grant2 = sessions.Refresh(firstRefresh, "127.0.0.1");
                Assert.NotNull(grant2);
                secondRefresh = grant2!.RefreshToken;
                Assert.NotEqual(firstRefresh, secondRefresh);

                store.AddUsage("2026-11", 4096);
            }

            // Reload from disk: state, devices, usage, and refresh tokens all survive.
            using (var reloaded = new JsonStateStore(temp, clock, "Ignored"))
            {
                Assert.Equal(ownerId, reloaded.GetOwner().Id);
                Assert.Equal("Alice", reloaded.GetOwner().Name);
                Assert.Equal(4096, reloaded.GetUsage("2026-11"));
                Assert.Single(reloaded.GetDevices());

                var tokens = new AccessTokens(secret2, clock);
                var sessions = new DeviceSessions(reloaded, tokens, signOut, clock, maxDevices: 2);

                // Within grace window, replaying previous token still succeeds.
                var grant3 = sessions.Refresh(firstRefresh, "127.0.0.1");
                Assert.NotNull(grant3);

                // Advance past ReuseGrace (2 minutes) and replay old previous token -> theft detected, device kicked!
                clock.Advance(TimeSpan.FromMinutes(3));
                Assert.Null(sessions.Refresh(firstRefresh, "127.0.0.1"));
                Assert.Contains(dev.Id, kicked);
                Assert.Empty(reloaded.GetDevices());
            }
        }
        finally
        {
            Directory.Delete(temp, recursive: true);
        }
    }

    private sealed class RecordingSignOut(List<string> kicked) : IDeviceSignOut
    {
        public void SignedOut(string deviceId) => kicked.Add(deviceId);
    }
}
