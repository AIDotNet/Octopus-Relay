using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Octopus.Relay.Auth;
using Octopus.Relay.Relay;
using Octopus.Relay.Storage;

namespace Octopus.Relay.Api;

/// <summary>Management API for the built-in self-hosted Web UI (<c>/api/*</c>).</summary>
internal sealed class WebApi(
    ServerSettings settings,
    JsonStateStore store,
    OwnerAuthService ownerAuth,
    WebSessions webSessions,
    DeviceSessions deviceSessions,
    DeviceLogins deviceLogins,
    RelayHub relay,
    RelayUsage usage,
    StunServer stun,
    QuicRelayServer quic,
    TimeProvider time)
{
    private const string PasswordAccessFeature = "password-access";
    private readonly DateTimeOffset _startedAt = time.GetUtcNow();

    public void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/status", Status);
        app.MapPost("/api/setup", CompleteSetup);
        app.MapPost("/api/auth/login", Login);
        app.MapPost("/api/auth/logout", Logout);
        app.MapPost("/api/auth/signout-all", SignOutEverywhere);
        app.MapGet("/api/dashboard", Dashboard);
        app.MapPatch("/api/account", Rename);
        app.MapPost("/api/account/password", ChangePassword);
        app.MapDelete("/api/devices/{id}", RemoveDevice);
        app.MapGet("/api/device-login", DeviceLogin);
        app.MapPost("/api/device-login/approve", ApproveDeviceLogin);
        app.MapPost("/api/device-login/deny", DenyDeviceLogin);
        app.MapPost("/api/access-key/rotate", RotateAccessKey);
        app.MapPost("/api/access-key/disable", DisableAccessKey);
    }

    private Task Status(HttpContext context)
    {
        var signedIn = webSessions.Authenticate(context.Request.Cookies[WebSessions.CookieName]) is not null;
        var body = new WebStatusBody(
            settings.ServerName,
            ClientApi.AppVersion,
            ownerAuth.NeedsSetup,
            ownerAuth.PasswordEnabled,
            ownerAuth.PasswordManagedByEnv,
            ownerAuth.AccessKeyEnabled,
            ownerAuth.AccessKeyManagedByEnv,
            signedIn);
        return Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.WebStatusBody);
    }

    private async Task CompleteSetup(HttpContext context)
    {
        var request = await Wire.Read(context, ApiJson.Default.SetupRequest);
        if (request is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        var (ok, error, generatedKey) = ownerAuth.CompleteSetup(request.SetupToken, request.OwnerName, request.Password, request.GenerateAccessKey);
        if (!ok)
        {
            var code = error switch
            {
                "setup_completed" => StatusCodes.Status403Forbidden,
                "invalid_setup_token" => StatusCodes.Status401Unauthorized,
                _ => StatusCodes.Status400BadRequest,
            };
            await Wire.Error(context, code, error!);
            return;
        }

        StartSession(context);
        var owner = store.GetOwner();
        var setupLink = generatedKey is null ? null : Wire.BuildSetupLink(Wire.PublicOrigin(context, settings), generatedKey);
        await Wire.Json(context, StatusCodes.Status200OK, new SetupResponseBody(ShapeOwner(owner), generatedKey, setupLink), ApiJson.Default.SetupResponseBody);
    }

    private async Task Login(HttpContext context)
    {
        if (ownerAuth.NeedsSetup)
        {
            await Wire.Error(context, StatusCodes.Status409Conflict, "setup_required");
            return;
        }

        if (!ownerAuth.PasswordEnabled)
        {
            await Wire.Error(context, StatusCodes.Status403Forbidden, "password_disabled");
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.PasswordLoginRequest);
        if (request is null || !ownerAuth.VerifyPassword(request.Password))
        {
            await Wire.Error(context, StatusCodes.Status401Unauthorized, "invalid_password");
            return;
        }

        StartSession(context);
        await Wire.Json(context, StatusCodes.Status200OK, ShapeOwner(store.GetOwner()), ApiJson.Default.WebAccountBody);
    }

    private async Task Logout(HttpContext context)
    {
        webSessions.Delete(context.Request.Cookies[WebSessions.CookieName]);
        Wire.ClearSessionCookie(context, settings);
        await Wire.NoContent(context);
    }

    private async Task SignOutEverywhere(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        deviceSessions.SignOutEverywhere();
        Wire.ClearSessionCookie(context, settings);
        await Wire.NoContent(context);
    }

    private async Task Dashboard(HttpContext context)
    {
        if (await SignedIn(context) is not { } owner)
        {
            return;
        }

        var devices = store.GetDevices();
        var origin = Wire.PublicOrigin(context, settings);
        var publicUrl = origin.GetLeftPart(UriPartial.Authority);
        var stats = new WebStatsBody(
            relay.HostCount,
            relay.TunnelCount,
            store.GetUsage(usage.CurrentMonth()),
            settings.Relay.MonthlyBytesLimit,
            _startedAt.UtcDateTime)
        {
            StunEndpoint = stun.AdvertisedEndpoint(origin),
            QuicEndpoint = quic.AdvertisedEndpoint(origin),
        };
        var body = new WebDashboardBody(
            settings.ServerName,
            ClientApi.AppVersion,
            publicUrl,
            ShapeOwner(owner),
            stats,
            deviceSessions.MaxDevices,
            devices.Count,
            ownerAuth.PasswordEnabled,
            ownerAuth.PasswordManagedByEnv,
            ownerAuth.AccessKeyEnabled,
            ownerAuth.AccessKeyManagedByEnv,
            ownerAuth.AccessKeyHint,
            ShapeDevices(devices));
        await Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.WebDashboardBody);
    }

    private async Task Rename(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.NameRequest);
        var updated = ownerAuth.RenameOwner(request?.Name);
        if (updated is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_name");
            return;
        }

        await Wire.Json(context, StatusCodes.Status200OK, ShapeOwner(updated), ApiJson.Default.WebAccountBody);
    }

    private async Task ChangePassword(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.ChangePasswordRequest);
        if (request is null)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, "invalid_request");
            return;
        }

        var (ok, error) = ownerAuth.ChangePassword(request.CurrentPassword, request.NewPassword);
        if (!ok)
        {
            var status = error == "invalid_password" ? StatusCodes.Status401Unauthorized : StatusCodes.Status400BadRequest;
            await Wire.Error(context, status, error!);
            return;
        }

        await Wire.NoContent(context);
    }

    private async Task RemoveDevice(HttpContext context)
    {
        if (await SignedIn(context) is null)
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

    private async Task DeviceLogin(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var pending = deviceLogins.Find(context.Request.Query["code"]);
        if (pending is null)
        {
            await Wire.Error(context, StatusCodes.Status404NotFound, "unknown_code");
            return;
        }

        var known = store.GetDevice(pending.DeviceId) is not null;
        var body = new DeviceLoginBody(
            pending.UserCode,
            pending.DeviceId,
            pending.DeviceName,
            pending.Kind,
            pending.Platform,
            pending.AppVersion,
            pending.Ip,
            pending.RequestedAt.UtcDateTime,
            known);
        await Wire.Json(context, StatusCodes.Status200OK, body, ApiJson.Default.DeviceLoginBody);
    }

    private async Task ApproveDeviceLogin(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.CodeRequest);
        var result = deviceLogins.Approve(request?.Code);
        switch (result.Status)
        {
            case ApproveStatus.Approved:
                await Wire.NoContent(context);
                break;
            case ApproveStatus.DeviceLimit:
                await Wire.Error(context, StatusCodes.Status409Conflict, new ErrorBody("device_limit")
                {
                    MaxDevices = result.MaxDevices,
                    Devices = ShapeDevices(result.Devices!),
                });
                break;
            default:
                await Wire.Error(context, StatusCodes.Status404NotFound, "unknown_code");
                break;
        }
    }

    private async Task DenyDeviceLogin(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var request = await Wire.Read(context, ApiJson.Default.CodeRequest);
        deviceLogins.Deny(request?.Code);
        await Wire.NoContent(context);
    }

    private async Task RotateAccessKey(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var (ok, error, plainKey, hint) = ownerAuth.RotateAccessKey();
        if (!ok)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, error!);
            return;
        }

        var setupLink = Wire.BuildSetupLink(Wire.PublicOrigin(context, settings), plainKey!);
        await Wire.Json(context, StatusCodes.Status200OK, new AccessKeyRotateBody(plainKey!, hint!, setupLink), ApiJson.Default.AccessKeyRotateBody);
    }

    private async Task DisableAccessKey(HttpContext context)
    {
        if (await SignedIn(context) is null)
        {
            return;
        }

        var (ok, error) = ownerAuth.DisableAccessKey();
        if (!ok)
        {
            await Wire.Error(context, StatusCodes.Status400BadRequest, error!);
            return;
        }

        await Wire.NoContent(context);
    }

    private async Task<OwnerProfile?> SignedIn(HttpContext context)
    {
        var owner = webSessions.Authenticate(context.Request.Cookies[WebSessions.CookieName]);
        if (owner is null)
        {
            if (context.Request.Cookies.ContainsKey(Wire.SignedInCookieName))
            {
                Wire.ClearSessionCookie(context, settings);
            }

            await Wire.Error(context, StatusCodes.Status401Unauthorized, "unauthorized");
        }

        return owner;
    }

    private void StartSession(HttpContext context)
    {
        var token = webSessions.Create(context.Request.Headers.UserAgent.ToString(), Wire.ClientIp(context, settings));
        Wire.SetSessionCookie(context, settings, token);
    }

    private static WebAccountBody ShapeOwner(OwnerProfile owner)
    {
        return new WebAccountBody(owner.Id, owner.Name, owner.CreatedAt.UtcDateTime);
    }

    private IReadOnlyList<WebDeviceBody> ShapeDevices(IReadOnlyList<DeviceRecord> devices)
    {
        return
        [
            .. devices.Select(d =>
            {
                var online = relay.IsOnline(d.Id);
                return new WebDeviceBody(
                    d.Id,
                    d.Name,
                    d.Kind,
                    d.Platform,
                    d.AppVersion,
                    online,
                    online && relay.HasFeature(d.Id, PasswordAccessFeature),
                    d.CreatedAt.UtcDateTime,
                    d.LastSeenAt.UtcDateTime,
                    d.LastIp)
                {
                    Features = online ? relay.FeaturesOf(d.Id) : null,
                };
            }),
        ];
    }
}
