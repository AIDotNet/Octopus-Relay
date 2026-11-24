using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Octopus.Relay.Web;

/// <summary>Serves the zero-dependency embedded management UI compiled into the binary.</summary>
internal sealed class EmbeddedUi
{
    private readonly byte[] _html;
    private readonly byte[] _css;
    private readonly byte[] _js;

    public EmbeddedUi()
    {
        _html = LoadResource("Octopus.Relay.Web.Assets.index.html");
        _css = LoadResource("Octopus.Relay.Web.Assets.app.css");
        _js = LoadResource("Octopus.Relay.Web.Assets.app.js");
    }

    public void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/", ServePage);
        app.MapGet("/setup", ServePage);
        app.MapGet("/login", ServePage);
        app.MapGet("/device", ServePage);
        app.MapGet("/account", ServePage);
        app.MapGet("/assets/app.css", context => ServeAsset(context, _css, "text/css; charset=utf-8"));
        app.MapGet("/assets/app.js", context => ServeAsset(context, _js, "application/javascript; charset=utf-8"));
    }

    private Task ServePage(HttpContext context)
    {
        SetSecurityHeaders(context);
        context.Response.Headers.CacheControl = "no-cache";
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.ContentLength = _html.Length;
        return context.Response.Body.WriteAsync(_html, context.RequestAborted).AsTask();
    }

    private static Task ServeAsset(HttpContext context, byte[] bytes, string contentType)
    {
        SetSecurityHeaders(context);
        context.Response.Headers.CacheControl = "public, max-age=3600";
        context.Response.ContentType = contentType;
        context.Response.ContentLength = bytes.Length;
        return context.Response.Body.WriteAsync(bytes, context.RequestAborted).AsTask();
    }

    private static void SetSecurityHeaders(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'";
    }

    private static byte[] LoadResource(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Missing embedded UI asset: {name}");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}
