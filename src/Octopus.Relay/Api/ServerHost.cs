using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Octopus.Relay.Auth;
using Octopus.Relay.Relay;
using Octopus.Relay.Storage;
using Octopus.Relay.Web;

namespace Octopus.Relay.Api;

/// <summary>Wires up services, Kestrel limits, optional direct TLS, middleware, and routes.</summary>
public static class ServerHost
{
    private const long MaxRequestBodyBytes = 64 * 1024;

    public static WebApplicationBuilder CreateBuilder(ServerSettings settings)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = MaxRequestBodyBytes;
            if (!string.IsNullOrWhiteSpace(settings.TlsCertPath) && !string.IsNullOrWhiteSpace(settings.TlsKeyPath))
            {
                var cert = X509Certificate2.CreateFromPemFile(settings.TlsCertPath, settings.TlsKeyPath);
                kestrel.ConfigureHttpsDefaults(https => https.ServerCertificate = cert);
            }
        });
        return builder;
    }

    public static WebApplication Build(WebApplicationBuilder builder, ServerSettings settings, Action<IServiceCollection>? configure = null)
    {
        var services = builder.Services;
        var secret = settings.Secret ?? JsonStateStore.LoadOrCreateSecret(settings.DataDir);

        services.AddSingleton(settings);
        services.AddSingleton(settings.Relay);
        services.TryAddSingleton(TimeProvider.System);

        services.AddSingleton(provider => new JsonStateStore(settings.DataDir, provider.GetRequiredService<TimeProvider>(), settings.OwnerName));
        services.AddSingleton(provider => new OwnerAuthService(
            provider.GetRequiredService<JsonStateStore>(),
            settings.Password,
            settings.AccessKey,
            settings.OwnerName));
        services.AddSingleton(provider => new AccessTokens(secret, provider.GetRequiredService<TimeProvider>()));
        services.AddSingleton<RelayUsage>();
        services.AddSingleton<IRelayUsage>(provider => provider.GetRequiredService<RelayUsage>());
        services.AddSingleton<RelayHub>();
        services.AddSingleton<IDeviceSignOut, RelaySignOut>();
        services.AddSingleton(provider => new DeviceSessions(
            provider.GetRequiredService<JsonStateStore>(),
            provider.GetRequiredService<AccessTokens>(),
            provider.GetRequiredService<IDeviceSignOut>(),
            provider.GetRequiredService<TimeProvider>(),
            settings.MaxDevices));
        services.AddSingleton(provider => new DeviceLogins(
            provider.GetRequiredService<JsonStateStore>(),
            provider.GetRequiredService<DeviceSessions>(),
            provider.GetRequiredService<TimeProvider>(),
            settings.PollIntervalSeconds));
        services.AddSingleton<AccessKeyLogins>();
        services.AddSingleton<WebSessions>();
        services.AddSingleton<RateLimiter>();
        services.AddSingleton<ClientApi>();
        services.AddSingleton<WebApi>();
        services.AddSingleton<EmbeddedUi>();

        configure?.Invoke(services);

        var app = builder.Build();
        app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20) });

        var gate = new ApiGate(settings, app.Services.GetRequiredService<RateLimiter>(), app.Logger);
        app.Use(gate.Invoke);

        app.MapGet("/healthz", context => context.Response.WriteAsync("ok", context.RequestAborted));
        app.MapGet("/readyz", context => context.Response.WriteAsync("ok", context.RequestAborted));
        app.Services.GetRequiredService<ClientApi>().Map(app);
        app.Services.GetRequiredService<WebApi>().Map(app);
        app.Services.GetRequiredService<EmbeddedUi>().Map(app);

        return app;
    }

    public static Uri ListeningUrl(WebApplication app)
    {
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault()
            ?? ServerSettings.DefaultListenUrl;
        address = address.Replace("://[::]", "://localhost", StringComparison.Ordinal)
            .Replace("://0.0.0.0", "://localhost", StringComparison.Ordinal)
            .Replace("://+", "://localhost", StringComparison.Ordinal)
            .Replace("://*", "://localhost", StringComparison.Ordinal);
        return new Uri(new Uri(address).GetLeftPart(UriPartial.Authority));
    }
}

internal sealed class ApiGate(ServerSettings settings, RateLimiter limiter, ILogger logger)
{
    public async Task Invoke(HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path.Value ?? "/";
        if (!IsApi(path))
        {
            await next(context);
            return;
        }

        context.Response.Headers.CacheControl = "no-store";
        try
        {
            var (group, limit) = LimitFor(path);
            if (!limiter.Allow(group, Wire.ClientIp(context, settings) ?? "unknown", limit, out var retryAfter))
            {
                context.Response.Headers.RetryAfter = retryAfter.ToString(System.Globalization.CultureInfo.InvariantCulture);
                await Wire.Error(context, StatusCodes.Status429TooManyRequests, "too_many_requests");
                return;
            }

            // Cross-site request protection for cookie-authenticated /api/* mutations.
            if (path.StartsWith("/api", StringComparison.Ordinal) && !IsSafe(context.Request.Method))
            {
                if (!HttpMethods.IsDelete(context.Request.Method) && !IsJson(context.Request.ContentType))
                {
                    await Wire.Error(context, StatusCodes.Status415UnsupportedMediaType, "unsupported_media_type");
                    return;
                }

                if (context.Request.Headers.Origin.ToString() is { Length: > 0 } origin && !IsOurOrigin(context, origin))
                {
                    await Wire.Error(context, StatusCodes.Status403Forbidden, "forbidden");
                    return;
                }
            }

            await next(context);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
        }
        catch (BadHttpRequestException e)
        {
            if (!context.Response.HasStarted)
            {
                await Wire.Error(context, e.StatusCode, "invalid_request");
            }
        }
        catch (Exception e)
        {
            logger.LogError("{Method} {Path} failed: {Kind}: {Message}", context.Request.Method, path, e.GetType().Name, e.Message);
            if (!context.Response.HasStarted)
            {
                await Wire.Error(context, StatusCodes.Status500InternalServerError, "server_error");
            }
        }
    }

    private (string Group, int Limit) LimitFor(string path)
    {
        var limits = settings.RateLimits;
        if (path.StartsWith("/v1/auth/", StringComparison.Ordinal))
        {
            return ("client-auth", limits.ClientAuth);
        }

        if (path.StartsWith("/v1", StringComparison.Ordinal))
        {
            return ("client", limits.Client);
        }

        if (path is "/api/auth/login" or "/api/setup")
        {
            return ("web-auth", limits.WebAuth);
        }

        return ("web", limits.Web);
    }

    private bool IsOurOrigin(HttpContext context, string origin)
    {
        var expected = Wire.PublicOrigin(context, settings).GetLeftPart(UriPartial.Authority);
        if (string.Equals(origin, expected, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var direct = $"{context.Request.Scheme}://{context.Request.Host.Value}";
        return string.Equals(origin, direct, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsApi(string path)
    {
        return path.StartsWith("/api/", StringComparison.Ordinal)
            || path.StartsWith("/v1/", StringComparison.Ordinal)
            || path is "/api" or "/v1";
    }

    private static bool IsSafe(string method)
    {
        return HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method);
    }

    private static bool IsJson(string? contentType)
    {
        if (contentType is null)
        {
            return false;
        }

        var semicolon = contentType.IndexOf(';');
        var mediaType = (semicolon < 0 ? contentType : contentType[..semicolon]).Trim();
        return mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase);
    }
}

public static class ServerProgram
{
    public static async Task<int> RunAsync(string[] args)
    {
        var settings = ServerSettings.Load(args);
        if (settings.ShowHelp)
        {
            PrintHelp();
            return 0;
        }

        if (settings.ShowVersion)
        {
            Console.WriteLine($"octopus-relay {ClientApi.AppVersion}");
            return 0;
        }

        var (errors, warnings) = settings.Check();
        foreach (var warning in warnings)
        {
            Console.Error.WriteLine("warning: " + warning);
        }

        if (errors.Count > 0)
        {
            foreach (var error in errors)
            {
                Console.Error.WriteLine("error: " + error);
            }

            return 1;
        }

        var builder = ServerHost.CreateBuilder(settings);
        WebApplication app;
        try
        {
            app = ServerHost.Build(builder, settings);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or FormatException)
        {
            Console.Error.WriteLine($"error: Failed to initialize relay state: {e.Message}");
            return 1;
        }

        app.Urls.Add(settings.ListenUrl);
        await app.StartAsync();

        var listening = ServerHost.ListeningUrl(app);
        var publicDisplay = (settings.PublicUrl ?? listening).GetLeftPart(UriPartial.Authority);
        var ownerAuth = app.Services.GetRequiredService<OwnerAuthService>();

        Console.WriteLine($"Octopus Relay v{ClientApi.AppVersion} listening on {settings.ListenUrl} (public: {publicDisplay})");
        Console.WriteLine($"State directory: {(settings.DataDir is null ? "(in-memory)" : Path.GetFullPath(settings.DataDir))}");

        if (ownerAuth.NeedsSetup && ownerAuth.BootstrapSetupToken is { } token)
        {
            Console.WriteLine();
            Console.WriteLine("First-time setup required. Open this URL in your browser:");
            Console.WriteLine($"  {publicDisplay}/setup?token={token}");
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine($"Auth methods: {string.Join(", ", ownerAuth.SupportedAuthMethods)}");
        }

        await app.WaitForShutdownAsync();
        app.Services.GetRequiredService<JsonStateStore>().Dispose();
        return 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            Octopus Relay - Lightweight single-user self-hosted relay for Octopus

            Usage:
              octopus-relay [options]

            Options (all also configurable via RELAY_* environment variables):
              --data <dir>           Directory for state.json and secret.key (default: ./data) [RELAY_DATA_DIR]
              --listen <url>         Listen address (default: http://0.0.0.0:8080) [RELAY_LISTEN]
              --public-url <url>     Canonical public origin (e.g. https://relay.example.com) [RELAY_PUBLIC_URL]
              --password <pwd>       Owner password for Web UI & device-code sign-in (>= 8 chars) [RELAY_PASSWORD]
              --access-key <key>     Access Key for browser-free client sign-in (>= 16 chars) [RELAY_ACCESS_KEY]
              --secret <base64>      Signing secret (>= 32 bytes; auto-generated in data dir if omitted) [RELAY_SECRET]
              --name <name>          Relay display name (default: Octopus Relay) [RELAY_NAME]
              --owner <name>         Owner display name (default: Owner) [RELAY_OWNER_NAME]
              --trust-proxy          Trust X-Forwarded-Proto/Host/For and CF-Connecting-IP [RELAY_TRUST_PROXY]
              --tls-cert <file>      PEM certificate path for direct HTTPS [RELAY_TLS_CERT]
              --tls-key <file>       PEM private key path for direct HTTPS [RELAY_TLS_KEY]
              --memory               Run in memory without writing state to disk
              -v, --version          Print version
              -h, --help             Show this help
            """);
    }
}
