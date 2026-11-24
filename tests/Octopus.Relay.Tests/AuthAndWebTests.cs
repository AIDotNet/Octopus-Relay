using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Octopus.Relay.Auth;
using Xunit;

namespace Octopus.Relay.Tests;

public sealed class AuthAndWebTests
{
    [Fact]
    public async Task First_run_setup_enables_password_and_access_key_and_locks_setup_endpoint()
    {
        await using var server = await RelayTestServer.StartAsync();
        Assert.True(server.OwnerAuth.NeedsSetup);
        var setupToken = server.OwnerAuth.BootstrapSetupToken;
        Assert.NotNull(setupToken);

        using var browser = server.CreateHttpClient(cookies: true);

        // Wrong setup token is rejected.
        using (var bad = await browser.PostAsync("/api/setup", Json(new { setupToken = "wrong", ownerName = "Ada", password = "my-strong-password", generateAccessKey = true })))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
        }

        // Complete setup with valid token.
        string generatedKey;
        using (var ok = await browser.PostAsync("/api/setup", Json(new { setupToken, ownerName = "Ada", password = "my-strong-password", generateAccessKey = true })))
        {
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
            var doc = JsonDocument.Parse(await ok.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal("Ada", doc.GetProperty("account").GetProperty("name").GetString());
            generatedKey = doc.GetProperty("accessKey").GetString()!;
            Assert.StartsWith("ork_", generatedKey);
            Assert.Contains("octopus://relay?v=1&url=", doc.GetProperty("setupLink").GetString());
        }

        // Second setup attempt is permanently forbidden.
        using (var again = await browser.PostAsync("/api/setup", Json(new { setupToken, ownerName = "Eve", password = "another-password", generateAccessKey = false })))
        {
            Assert.Equal(HttpStatusCode.Forbidden, again.StatusCode);
        }

        // /v1/info reports both auth methods.
        using var infoRes = await browser.GetAsync("/v1/info");
        Assert.Equal(HttpStatusCode.OK, infoRes.StatusCode);
        var info = JsonDocument.Parse(await infoRes.Content.ReadAsStringAsync()).RootElement;
        var auth = info.GetProperty("auth").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("device_code", auth);
        Assert.Contains("access_key", auth);

        // Generated access key works immediately for browser-free device login.
        using var device = new TestDevice("Laptop");
        var granted = await server.SignInWithKeyAsync(device, generatedKey);
        Assert.StartsWith("oa1.", granted.GetProperty("accessToken").GetString());
        Assert.StartsWith("or1.", granted.GetProperty("refreshToken").GetString());
        Assert.Equal(device.Id, granted.GetProperty("deviceId").GetString());
    }

    [Fact]
    public async Task Device_code_flow_with_password_login_and_proxy_url_derivation()
    {
        await using var server = await RelayTestServer.StartAsync(s =>
        {
            s.Password = "super-secret-pass";
            s.TrustProxy = true;
        });

        using var client = server.CreateHttpClient();
        using var device = new TestDevice("Workstation");
        using var thief = new TestDevice("Thief");

        // Start device login behind a reverse proxy without RELAY_PUBLIC_URL configured.
        using var startReq = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/device")
        {
            Content = Json(new
            {
                deviceName = device.Name,
                kind = device.Kind,
                publicKey = device.PublicKeyBase64,
                platform = "macOS",
                appVersion = "1.0.1135",
            }),
        };
        startReq.Headers.Add("X-Forwarded-Proto", "https");
        startReq.Headers.Add("X-Forwarded-Host", "relay.mybox.dev");

        using var startRes = await client.SendAsync(startReq);
        Assert.Equal(HttpStatusCode.OK, startRes.StatusCode);
        var start = JsonDocument.Parse(await startRes.Content.ReadAsStringAsync()).RootElement;
        var deviceCode = start.GetProperty("deviceCode").GetString()!;
        var userCode = start.GetProperty("userCode").GetString()!;
        Assert.Equal("https://relay.mybox.dev/device", start.GetProperty("verificationUri").GetString());
        Assert.Equal($"https://relay.mybox.dev/device?code={userCode}", start.GetProperty("verificationUriComplete").GetString());

        // Browser logs in with owner password and approves the device code.
        using var browser = server.CreateHttpClient(cookies: true);
        using (var badPwd = await browser.PostAsync("/api/auth/login", Json(new { password = "wrong-password" })))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, badPwd.StatusCode);
        }

        using (var loginOk = await browser.PostAsync("/api/auth/login", Json(new { password = "super-secret-pass" })))
        {
            Assert.Equal(HttpStatusCode.OK, loginOk.StatusCode);
        }

        using (var lookup = await browser.GetAsync($"/api/device-login?code={userCode}"))
        {
            Assert.Equal(HttpStatusCode.OK, lookup.StatusCode);
            var pending = JsonDocument.Parse(await lookup.Content.ReadAsStringAsync()).RootElement;
            Assert.Equal(device.Id, pending.GetProperty("deviceId").GetString());
        }

        using (var approve = await browser.PostAsync("/api/device-login/approve", Json(new { code = userCode })))
        {
            Assert.Equal(HttpStatusCode.NoContent, approve.StatusCode);
        }

        // Another device key cannot redeem the approved code.
        using (var stolen = await client.PostAsync("/v1/auth/token", Json(new
        {
            grantType = "device_code",
            deviceCode,
            signature = thief.SignBase64(DeviceKey.LoginHash(deviceCode)),
        })))
        {
            Assert.Equal(HttpStatusCode.BadRequest, stolen.StatusCode);
            Assert.Equal("invalid_grant", JsonDocument.Parse(await stolen.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString());
        }

        // The real device redeems its tokens.
        string refreshToken;
        using (var redeem = await client.PostAsync("/v1/auth/token", Json(new
        {
            grantType = "device_code",
            deviceCode,
            signature = device.SignBase64(DeviceKey.LoginHash(deviceCode)),
        })))
        {
            Assert.Equal(HttpStatusCode.OK, redeem.StatusCode);
            var granted = JsonDocument.Parse(await redeem.Content.ReadAsStringAsync()).RootElement;
            refreshToken = granted.GetProperty("refreshToken").GetString()!;
            Assert.Equal(device.Id, granted.GetProperty("deviceId").GetString());
        }

        // Refresh rotates the token, and revoke ends the login.
        using var refreshed = await client.PostAsync("/v1/auth/token", Json(new { grantType = "refresh_token", refreshToken }));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var nextRefresh = JsonDocument.Parse(await refreshed.Content.ReadAsStringAsync()).RootElement.GetProperty("refreshToken").GetString()!;
        Assert.NotEqual(refreshToken, nextRefresh);

        using var revoked = await client.PostAsync("/v1/auth/revoke", Json(new { refreshToken = nextRefresh }));
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        using var afterRevoke = await client.PostAsync("/v1/auth/token", Json(new { grantType = "refresh_token", refreshToken = nextRefresh }));
        Assert.Equal(HttpStatusCode.BadRequest, afterRevoke.StatusCode);
    }

    [Fact]
    public async Task Access_key_rejects_wrong_key_replayed_challenge_and_wrong_signature()
    {
        const string key = "ork_test_access_key_0123456789abcdef";
        await using var server = await RelayTestServer.StartAsync(s => s.AccessKey = key);
        using var http = server.CreateHttpClient();
        using var device = new TestDevice("Phone", "phone");
        using var other = new TestDevice("Other", "phone");

        // Key-only mode does not expose device_code or setup.
        Assert.False(server.OwnerAuth.NeedsSetup);
        using var devStart = await http.PostAsync("/v1/auth/device", Json(new { deviceName = "X", kind = "desktop", publicKey = device.PublicKeyBase64 }));
        Assert.Equal(HttpStatusCode.Forbidden, devStart.StatusCode);

        async Task<string> GetChallengeAsync()
        {
            using var res = await http.PostAsync("/v1/auth/key/challenge", Json(new { }));
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            return JsonDocument.Parse(await res.Content.ReadAsStringAsync()).RootElement.GetProperty("challenge").GetString()!;
        }

        // Wrong access key -> 401.
        var c1 = await GetChallengeAsync();
        using (var wrongKey = await http.PostAsync("/v1/auth/key", Json(new
        {
            accessKey = "ork_wrong_key_0123456789abcdef",
            challenge = c1,
            deviceName = device.Name,
            kind = device.Kind,
            publicKey = device.PublicKeyBase64,
            signature = device.SignBase64(DeviceKey.KeyLoginHash(Convert.FromBase64String(c1))),
        })))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, wrongKey.StatusCode);
        }

        // Wrong signature -> 400 (and consumes challenge so replay fails).
        var c2 = await GetChallengeAsync();
        using (var wrongSig = await http.PostAsync("/v1/auth/key", Json(new
        {
            accessKey = key,
            challenge = c2,
            deviceName = device.Name,
            kind = device.Kind,
            publicKey = device.PublicKeyBase64,
            signature = other.SignBase64(DeviceKey.KeyLoginHash(Convert.FromBase64String(c2))),
        })))
        {
            Assert.Equal(HttpStatusCode.BadRequest, wrongSig.StatusCode);
            Assert.Equal("invalid_signature", JsonDocument.Parse(await wrongSig.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString());
        }

        // Replaying c2 with valid signature is rejected as invalid_challenge.
        using (var replay = await http.PostAsync("/v1/auth/key", Json(new
        {
            accessKey = key,
            challenge = c2,
            deviceName = device.Name,
            kind = device.Kind,
            publicKey = device.PublicKeyBase64,
            signature = device.SignBase64(DeviceKey.KeyLoginHash(Convert.FromBase64String(c2))),
        })))
        {
            Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
            Assert.Equal("invalid_challenge", JsonDocument.Parse(await replay.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task Devices_stay_signed_in_across_server_restarts_using_json_state()
    {
        var dataDir = Directory.CreateTempSubdirectory("octopus-relay-restart-").FullName;
        const string key = "ork_restart_test_key_0123456789abcdef";
        try
        {
            using var device = new TestDevice("Desktop");
            string accessToken;
            string refreshToken;

            await using (var first = await RelayTestServer.StartAsync(s => s.AccessKey = key, dataDir: dataDir))
            {
                var granted = await first.SignInWithKeyAsync(device, key);
                accessToken = granted.GetProperty("accessToken").GetString()!;
                refreshToken = granted.GetProperty("refreshToken").GetString()!;
            }

            // Start a brand-new server instance pointing at the same JSON data directory.
            await using (var second = await RelayTestServer.StartAsync(s => s.AccessKey = key, dataDir: dataDir))
            {
                using var http = second.CreateHttpClient();

                // Previously issued access token STILL validates (secret.key was reloaded).
                using var meReq = new HttpRequestMessage(HttpMethod.Get, "/v1/me");
                meReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                using var meRes = await http.SendAsync(meReq);
                Assert.Equal(HttpStatusCode.OK, meRes.StatusCode);

                // Refresh token STILL rotates cleanly (state.json was reloaded).
                using var refRes = await http.PostAsync("/v1/auth/token", Json(new { grantType = "refresh_token", refreshToken }));
                Assert.Equal(HttpStatusCode.OK, refRes.StatusCode);
            }
        }
        finally
        {
            Directory.Delete(dataDir, recursive: true);
        }
    }

    [Fact]
    public async Task Web_api_enforces_csrf_origin_and_json_content_type_and_serves_embedded_ui()
    {
        await using var server = await RelayTestServer.StartAsync(s => s.Password = "super-secret-pass");
        using var http = server.CreateHttpClient();

        // Embedded HTML and assets are served.
        using (var page = await http.GetAsync("/login"))
        {
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            Assert.Contains("app.js", await page.Content.ReadAsStringAsync());
        }

        // Non-JSON POST to /api/* is rejected with 415.
        using (var form = await http.PostAsync("/api/auth/login", new StringContent("password=super-secret-pass", Encoding.UTF8, "application/x-www-form-urlencoded")))
        {
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, form.StatusCode);
        }

        // Cross-origin POST to /api/* is rejected with 403.
        using var cross = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login") { Content = Json(new { password = "super-secret-pass" }) };
        cross.Headers.Add("Origin", "https://evil.example.com");
        using var crossRes = await http.SendAsync(cross);
        Assert.Equal(HttpStatusCode.Forbidden, crossRes.StatusCode);
    }

    private static StringContent Json(object value) =>
        new(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json");
}
