using System.Net.WebSockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Octopus.Relay.Auth;
using Octopus.Relay.Relay;
using Octopus.Relay.Storage;

namespace Octopus.Relay.Api;

/// <summary>
/// Octopus desktop &amp; mobile client protocol (<c>/v1/*</c>).
/// Fully compatible with official Octopus Server, plus <c>/v1/info</c> and <c>/v1/auth/key*</c> for browser-free
/// self-hosted onboarding.
/// </summary>
internal sealed class ClientApi(
    ServerSettings settings,
    JsonStateStore store,
    OwnerAuthService ownerAuth,
    AccessTokens accessTokens,
    DeviceSessions deviceSessions,
    DeviceLogins deviceLogins,
    AccessKeyLogins keyLogins,
    RelayHub relay,
    TimeProvider time)
{
    private const int ControlMessageBytes = 4096;
    private const string PasswordAccessFeature = "password-access";
    private static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(2);

    internal static string AppVersion { get; } =
        (typeof(ClientApi).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0")
            .Split('+', 2)[0];

    public void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/v1/info", Info);
        app.MapPost("/v1/auth/device", StartLogin);
        app.MapPost("/v1/auth/key/challenge", StartKeyChallenge);
        app.MapPost("/v1/auth/key", SignInWithKey);
        app.MapPost("/v1/auth/token", Token);
        app.MapPost("/v1/auth/revoke", Revoke);
        app.MapGet("/v1/me", Me);
        app.MapGet("/v1/devices", Devices);
        app.MapDelete("/v1/devices/{id}", RemoveDevice);
        app.MapGet("/v1/host", Host);
        app.MapPost("/v1/tunnels", RequestTunnel);
        app.MapGet("/v1/tunnel/{id}", Tunnel);
    }

    private Task Info(HttpContext context)
    {
        var body = new RelayInfoBody(1, "self-hosted", settings.ServerName, AppVersion, ownerAuth.SupportedAuthMethods);
        return Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.RelayInfoBody);
    }

    private async Task StartLogin(HttpContext context)
    {
        var request = await Wire.Read(context, ApiJson.Default.DeviceStartRequest);
        var name = request?.DeviceName?.Trim();
        if (request is null
            || string.IsNullOrEmpty(name) || name.Length > 128 || name.Any(char.IsControl)
            || request.Kind is not (DeviceKinds.Desktop or DeviceKinds.Phone)
            || !DeviceKey.TryParse(request.PublicKey, out var key))
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        if (!ownerAuth.PasswordEnabled)
        {
            await Wire.Error(context, StatusCodes.Status403Forbidden, "device_login_disabled");
            return;
        }

        var start = deviceLogins.Start(key, name, request.Kind, Label(request.Platform), Label(request.AppVersion), Wire.ClientIp(context, settings));
        if (start is null)
        {
            await Wire.Error(context, StatusCodes.Status429TooManyRequests, "too_many_requests");
            return;
        }

        var page = new Uri(Wire.PublicOrigin(context, settings), "/device").AbsoluteUri;
        var body = new DeviceStartBody(start.DeviceCode, start.UserCode, page, page + "?code=" + start.UserCode, start.ExpiresIn, start.Interval);
        await Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.DeviceStartBody);
    }

    private async Task StartKeyChallenge(HttpContext context)
    {
        if (!ownerAuth.AccessKeyEnabled)
        {
            await Wire.Error(context, StatusCodes.Status403Forbidden, "key_login_disabled");
            return;
        }

        if (keyLogins.Issue() is not { } issued)
        {
            await Wire.Error(context, StatusCodes.Status429TooManyRequests, "too_many_requests");
            return;
        }

        await Wire.Json(context, StatusCodes.Status200OK, new KeyChallengeBody(issued.Challenge, issued.ExpiresIn), ApiJson.Default.KeyChallengeBody);
    }

    private async Task SignInWithKey(HttpContext context)
    {
        if (!ownerAuth.AccessKeyEnabled)
        {
            await Wire.Error(context, StatusCodes.Status403Forbidden, "key_login_disabled");
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.KeyLoginRequest);
        var name = request?.DeviceName?.Trim();
        if (request is null
            || string.IsNullOrEmpty(name) || name.Length > 128 || name.Any(char.IsControl)
            || request.Kind is not (DeviceKinds.Desktop or DeviceKinds.Phone)
            || !DeviceKey.TryParse(request.PublicKey, out var key)
            || string.IsNullOrEmpty(request.Signature) || request.Signature.Length > 128)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        if (!ownerAuth.VerifyAccessKey(request.AccessKey))
        {
            await Wire.Error(context, StatusCodes.Status401Unauthorized, "invalid_access_key");
            return;
        }

        var challenge = keyLogins.Consume(request.Challenge);
        if (challenge is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_challenge");
            return;
        }

        Span<byte> signature = stackalloc byte[DeviceKey.SignatureLength];
        if (!Convert.TryFromBase64String(request.Signature, signature, out var length)
            || length != DeviceKey.SignatureLength
            || !key.Verify(DeviceKey.KeyLoginHash(challenge), signature))
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_signature");
            return;
        }

        var (status, grant) = deviceSessions.SignIn(
            key, name, request.Kind, Label(request.Platform), Label(request.AppVersion), Wire.ClientIp(context, settings));
        if (status == RegisterDeviceStatus.LimitReached || grant is null)
        {
            await Wire.Error(context, StatusCodes.Status409Conflict, new ErrorBody("device_limit") { MaxDevices = deviceSessions.MaxDevices });
            return;
        }

        var body = new TokenBody(
            grant.AccessToken,
            grant.RefreshToken,
            grant.ExpiresIn,
            grant.DeviceId,
            new ClientAccountBody(grant.Owner.Id, grant.Owner.Name, ""));
        await Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.TokenBody);
    }

    private async Task Token(HttpContext context)
    {
        var request = await Wire.Read(context, ApiJson.Default.TokenRequest);
        if (request is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        var ip = Wire.ClientIp(context, settings);
        TokenGrant? grant;
        string error;
        switch (request.GrantType)
        {
            case "device_code":
                var redeemed = deviceLogins.Redeem(request.DeviceCode, request.Signature, ip);
                grant = redeemed.Grant;
                error = redeemed.Status switch
                {
                    RedeemStatus.ExpiredToken => "expired_token",
                    RedeemStatus.InvalidGrant => "invalid_grant",
                    RedeemStatus.AccessDenied => "access_denied",
                    RedeemStatus.SlowDown => "slow_down",
                    _ => "authorization_pending",
                };
                break;
            case "refresh_token":
                grant = deviceSessions.Refresh(request.RefreshToken, ip);
                error = "invalid_grant";
                break;
            default:
                grant = null;
                error = "unsupported_grant_type";
                break;
        }

        if (grant is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, error);
            return;
        }

        var body = new TokenBody(
            grant.AccessToken,
            grant.RefreshToken,
            grant.ExpiresIn,
            grant.DeviceId,
            new ClientAccountBody(grant.Owner.Id, grant.Owner.Name, ""));
        await Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.TokenBody);
    }

    private async Task Revoke(HttpContext context)
    {
        var request = await Wire.Read(context, ApiJson.Default.RevokeRequest);
        deviceSessions.Revoke(request?.RefreshToken);
        await Wire.NoContent(context);
    }

    private async Task Me(HttpContext context)
    {
        if (await Authorized(context) is not { })
        {
            return;
        }

        var owner = store.GetOwner();
        await Wire.Json(context, StatusCodes.Status200OK, new ClientAccountBody(owner.Id, owner.Name, ""), ApiJson.Default.ClientAccountBody);
    }

    private async Task Devices(HttpContext context)
    {
        if (await Authorized(context) is not { } grant)
        {
            return;
        }

        var devices = store.GetDevices();
        var body = new ClientDevicesBody(
        [
            .. devices.Select(device =>
            {
                var online = relay.IsOnline(device.Id);
                return new ClientDeviceBody(
                    device.Id,
                    device.Name,
                    device.Kind,
                    device.Platform,
                    device.AppVersion,
                    online,
                    device.Id == grant.DeviceId,
                    online && relay.HasFeature(device.Id, PasswordAccessFeature),
                    device.CreatedAt.UtcDateTime,
                    device.LastSeenAt.UtcDateTime);
            }),
        ]);
        await Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.ClientDevicesBody);
    }

    private async Task RemoveDevice(HttpContext context)
    {
        if (await Authorized(context) is not { })
        {
            return;
        }

        var id = context.Request.RouteValues["id"] as string ?? "";
        if (!DeviceKey.IsDeviceId(id) || !deviceSessions.Remove(id))
        {
            await Wire.Error(context, StatusCodes.Status404NotFound, "not_found");
            return;
        }

        await Wire.NoContent(context);
    }

    private async Task Host(HttpContext context)
    {
        if (await Authorized(context) is not { } grant)
        {
            return;
        }

        if (!context.WebSockets.IsWebSocketRequest)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync();
        var nonce = RandomNumberGenerator.GetBytes(32);
        RegisterMessage? register;
        try
        {
            var challenge = JsonSerializer.SerializeToUtf8Bytes(new ChallengeMessage("challenge", Convert.ToBase64String(nonce)), ApiJson.Default.ChallengeMessage);
            await socket.SendAsync(challenge, WebSocketMessageType.Text, true, context.RequestAborted);

            var receiving = ReceiveRegisterAsync(socket, context.RequestAborted);
            if (await Task.WhenAny(receiving, Task.Delay(settings.RegisterTimeout, context.RequestAborted)) != receiving)
            {
                using var closing = new CancellationTokenSource(CloseTimeout);
                await socket.CloseOutputAsync((WebSocketCloseStatus)RelayCloseCodes.BadRegistration, "registration timed out", closing.Token);
                await receiving.WaitAsync(closing.Token);
                return;
            }

            register = await receiving;
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException or IOException)
        {
            socket.Abort();
            return;
        }

        Span<byte> signature = stackalloc byte[DeviceKey.SignatureLength];
        if (register is not { Type: "register", Signature.Length: <= 128 }
            || !DeviceKey.TryParse(register.PublicKey, out var key)
            || !Convert.TryFromBase64String(register.Signature, signature, out var length) || length != DeviceKey.SignatureLength
            || !key.Verify(DeviceKey.HostRegistrationHash(nonce), signature)
            || key.Id != grant.DeviceId)
        {
            await CloseAsync(socket, RelayCloseCodes.BadRegistration, "registration refused");
            return;
        }

        var device = store.GetDevice(grant.DeviceId);
        if (device is null)
        {
            await CloseAsync(socket, RelayCloseCodes.SignedOut, "signed out");
            return;
        }

        var name = register.Name?.Trim();
        if (string.IsNullOrEmpty(name) || name.Any(char.IsControl))
        {
            name = null;
        }
        else if (name.Length > 128)
        {
            name = name[..128];
        }

        store.TouchDevice(grant.DeviceId, name, Wire.ClientIp(context, settings), time.GetUtcNow());
        await relay.RunHostAsync(grant.AccountId, grant.DeviceId, socket, register.Features, context.RequestAborted);
    }

    private async Task RequestTunnel(HttpContext context)
    {
        if (await Authorized(context) is not { } grant)
        {
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.TunnelRequestBody);
        if (request?.HostDeviceId is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        var result = await relay.RequestTunnelAsync(grant.AccountId, grant.DeviceId, request.HostDeviceId, context.RequestAborted);
        switch (result.Status)
        {
            case TunnelRequestStatus.Created:
                await Wire.Json(context, StatusCodes.Status201Created, new TunnelBody(result.TunnelId!), ApiJson.Default.TunnelBody);
                break;
            case TunnelRequestStatus.Busy:
                await Wire.Error(context, StatusCodes.Status429TooManyRequests, "busy");
                break;
            case TunnelRequestStatus.OverQuota:
                await Wire.Error(context, StatusCodes.Status429TooManyRequests, "quota");
                break;
            default:
                await Wire.Error(context, StatusCodes.Status404NotFound, "host_offline");
                break;
        }
    }

    private async Task Tunnel(HttpContext context)
    {
        if (await Authorized(context) is not { } grant)
        {
            return;
        }

        TunnelRole role;
        switch (context.Request.Query["role"].ToString())
        {
            case "host":
                role = TunnelRole.Host;
                break;
            case "device":
                role = TunnelRole.Device;
                break;
            default:
                await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
                return;
        }

        if (!context.WebSockets.IsWebSocketRequest)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        var id = context.Request.RouteValues["id"] as string ?? "";
        switch (relay.Join(id, grant.AccountId, grant.DeviceId, role, out var seat))
        {
            case TunnelJoinStatus.NotFound:
                await Wire.Error(context, StatusCodes.Status404NotFound, "not_found");
                return;
            case TunnelJoinStatus.Forbidden:
                await Wire.Error(context, StatusCodes.Status403Forbidden, "forbidden");
                return;
            case TunnelJoinStatus.Taken:
                await Wire.Error(context, StatusCodes.Status409Conflict, "conflict");
                return;
        }

        WebSocket socket;
        try
        {
            socket = await context.WebSockets.AcceptWebSocketAsync();
        }
        catch
        {
            relay.Abandon(seat!);
            throw;
        }

        using (socket)
        {
            await relay.RunTunnelAsync(seat!, socket, context.RequestAborted);
        }
    }

    private async Task<AccessGrant?> Authorized(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            && accessTokens.TryValidate(header["Bearer ".Length..].Trim(), out var grant)
            && grant.AccountId == store.GetOwner().Id)
        {
            return grant;
        }

        await Wire.Error(context, StatusCodes.Status401Unauthorized, "unauthorized");
        return null;
    }

    private static async Task<RegisterMessage?> ReceiveRegisterAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[ControlMessageBytes + 1];
        var length = 0;
        while (true)
        {
            var received = await socket.ReceiveAsync(buffer.AsMemory(length), cancellationToken);
            if (received.MessageType != WebSocketMessageType.Text)
            {
                return null;
            }

            length += received.Count;
            if (length > ControlMessageBytes)
            {
                return null;
            }

            if (received.EndOfMessage)
            {
                break;
            }
        }

        try
        {
            return JsonSerializer.Deserialize(buffer.AsSpan(0, length), ApiJson.Default.RegisterMessage);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static async Task CloseAsync(WebSocket socket, int code, string reason)
    {
        try
        {
            if (socket.State == WebSocketState.Open)
            {
                using var timeout = new CancellationTokenSource(CloseTimeout);
                await socket.CloseAsync((WebSocketCloseStatus)code, reason, timeout.Token);
                return;
            }
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException or IOException or ObjectDisposedException)
        {
        }

        socket.Abort();
    }

    private static string? Label(string? value)
    {
        var text = value?.Trim();
        return string.IsNullOrEmpty(text) || text.Length > 32 || text.Any(char.IsControl) ? null : text;
    }
}
