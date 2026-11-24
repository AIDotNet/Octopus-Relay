using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Http;
using Octopus.Relay.Auth;

namespace Octopus.Relay.Api;

internal static class Wire
{
    public const string SignedInCookieName = "or_signed_in";

    public static Task Json<T>(HttpContext context, int status, T body, JsonTypeInfo<T> type)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(context.Response.Body, body, type, context.RequestAborted);
    }

    public static Task Error(HttpContext context, int status, string code)
    {
        return Json(context, status, new ErrorBody(code), ApiJson.Default.ErrorBody);
    }

    public static Task Error(HttpContext context, int status, ErrorBody body)
    {
        return Json(context, status, body, ApiJson.Default.ErrorBody);
    }

    public static Task NoContent(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }

    public static async Task<T?> Read<T>(HttpContext context, JsonTypeInfo<T> type) where T : class
    {
        try
        {
            return await JsonSerializer.DeserializeAsync(context.Request.Body, type, context.RequestAborted);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Client IP, honoring Cloudflare / reverse proxy headers only when <c>RELAY_TRUST_PROXY=true</c>.</summary>
    public static string? ClientIp(HttpContext context, ServerSettings settings)
    {
        if (settings.TrustProxy)
        {
            if (IPAddress.TryParse(context.Request.Headers["CF-Connecting-IP"].ToString().Trim(), out var reported))
            {
                return Plain(reported);
            }

            var forwarded = context.Request.Headers["X-Forwarded-For"].ToString();
            if (!string.IsNullOrWhiteSpace(forwarded))
            {
                var last = forwarded[(forwarded.LastIndexOf(',') + 1)..].Trim();
                if (IPAddress.TryParse(last, out reported))
                {
                    return Plain(reported);
                }
            }
        }

        return context.Connection.RemoteIpAddress is { } remote ? Plain(remote) : null;
    }

    /// <summary>
    /// Canonical external origin for this request: explicit <c>RELAY_PUBLIC_URL</c>, or safely derived from
    /// proxy headers (when trusted) and the request's <c>Scheme</c> + <c>Host</c>.
    /// </summary>
    public static Uri PublicOrigin(HttpContext context, ServerSettings settings)
    {
        if (settings.PublicUrl is { } configured)
        {
            return configured;
        }

        var scheme = context.Request.Scheme;
        var host = context.Request.Host.Value;

        if (settings.TrustProxy)
        {
            var proto = FirstHeaderValue(context.Request.Headers["X-Forwarded-Proto"].ToString());
            if (proto is "http" or "https")
            {
                scheme = proto;
            }

            var forwardedHost = FirstHeaderValue(context.Request.Headers["X-Forwarded-Host"].ToString());
            if (!string.IsNullOrEmpty(forwardedHost))
            {
                host = forwardedHost;
            }
        }

        if (scheme is not ("http" or "https"))
        {
            scheme = "http";
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            host = "localhost";
        }

        if (Uri.TryCreate($"{scheme}://{host}", UriKind.Absolute, out var derived)
            && derived.Scheme is "http" or "https"
            && !string.IsNullOrEmpty(derived.Host)
            && string.IsNullOrEmpty(derived.UserInfo))
        {
            return new Uri(derived.GetLeftPart(UriPartial.Authority));
        }

        return new Uri("http://localhost");
    }

    public static bool IsHttps(HttpContext context, ServerSettings settings)
    {
        return PublicOrigin(context, settings).Scheme == Uri.UriSchemeHttps;
    }

    public static string BuildSetupLink(Uri publicOrigin, string accessKey)
    {
        var baseUrl = publicOrigin.GetLeftPart(UriPartial.Authority);
        return $"octopus://relay?v=1&url={Uri.EscapeDataString(baseUrl)}&key={Uri.EscapeDataString(accessKey)}";
    }

    public static void SetSessionCookie(HttpContext context, ServerSettings settings, string token)
    {
        var https = IsHttps(context, settings);
        var maxAge = TimeSpan.FromDays(400);
        context.Response.Cookies.Append(WebSessions.CookieName, token, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Secure = https,
            MaxAge = maxAge,
        });
        context.Response.Cookies.Append(SignedInCookieName, "1", new CookieOptions
        {
            HttpOnly = false,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Secure = https,
            MaxAge = maxAge,
        });
    }

    public static void ClearSessionCookie(HttpContext context, ServerSettings settings)
    {
        var https = IsHttps(context, settings);
        context.Response.Cookies.Append(WebSessions.CookieName, "", new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Secure = https,
            MaxAge = TimeSpan.Zero,
        });
        context.Response.Cookies.Append(SignedInCookieName, "", new CookieOptions
        {
            HttpOnly = false,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Secure = https,
            MaxAge = TimeSpan.Zero,
        });
    }

    private static string? FirstHeaderValue(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var comma = raw.IndexOf(',');
        var first = (comma < 0 ? raw : raw[..comma]).Trim().ToLowerInvariant();
        return first.Length > 0 && first.Length <= 255 && !first.Any(char.IsWhiteSpace) ? first : null;
    }

    private static string Plain(IPAddress address)
    {
        return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
    }
}
