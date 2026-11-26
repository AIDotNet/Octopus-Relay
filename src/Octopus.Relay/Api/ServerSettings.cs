using System.Net;
using Microsoft.Extensions.Configuration;
using Octopus.Relay.Auth;
using Octopus.Relay.Relay;

namespace Octopus.Relay.Api;

public sealed class RateLimits
{
    public int ClientAuth { get; set; } = 30;
    public int Client { get; set; } = 240;
    public int WebAuth { get; set; } = 15;
    public int Web { get; set; } = 120;
}

/// <summary>Configuration parsed from CLI flags and <c>RELAY_*</c> environment variables.</summary>
public sealed class ServerSettings
{
    public const string DefaultListenUrl = "http://0.0.0.0:8080";
    public const string DefaultDataDir = "./data";

    public RelayOptions Relay { get; } = new();
    public RateLimits RateLimits { get; } = new();

    public string ServerName { get; set; } = "Octopus Relay";

    public string OwnerName { get; set; } = "Owner";

    public string? DataDir { get; set; } = DefaultDataDir;

    public string ListenUrl { get; set; } = DefaultListenUrl;

    /// <summary>Optional canonical public origin (scheme + host[:port]). Auto-derived per request when omitted.</summary>
    public Uri? PublicUrl { get; set; }

    /// <summary>Optional 32+ byte signing secret. Auto-generated into <c>data/secret.key</c> when omitted.</summary>
    public byte[]? Secret { get; set; }

    public string? Password { get; set; }

    public string? AccessKey { get; set; }

    public bool TrustProxy { get; set; }

    public int MaxDevices { get; set; } = 32;

    public int PollIntervalSeconds { get; set; } = 2;

    public TimeSpan RegisterTimeout { get; set; } = TimeSpan.FromSeconds(15);

    public string? TlsCertPath { get; set; }

    public string? TlsKeyPath { get; set; }

    /// <summary>Optional UDP port for built-in RFC 5389 STUN server (null disables STUN; 0 picks an ephemeral port).</summary>
    public int? StunPort { get; set; }

    /// <summary>Optional advertised hostname/IP for built-in STUN URI; defaults to <see cref="PublicUrl"/> / request host.</summary>
    public string? StunHost { get; set; }

    /// <summary>Optional bind IP for built-in STUN UDP socket (defaults to <see cref="IPAddress.Any"/>).</summary>
    public IPAddress? StunBindAddress { get; set; }

    /// <summary>Optional extra STUN server URIs (e.g. <c>stun:stun.example.com:3478</c>) advertised alongside built-in STUN.</summary>
    public List<string> ExternalStunServers { get; } = [];

    /// <summary>Optional UDP port for QUIC tunnel endpoint (<c>ALPN: octopus-relay-v2</c>; null disables QUIC; 0 picks an ephemeral port).</summary>
    public int? QuicPort { get; set; }

    /// <summary>Optional advertised hostname/IP for QUIC endpoint URI; defaults to <see cref="PublicUrl"/> / request host.</summary>
    public string? QuicHost { get; set; }

    /// <summary>Optional bind IP for QUIC UDP listener (defaults to <see cref="IPAddress.Any"/>).</summary>
    public IPAddress? QuicBindAddress { get; set; }

    public bool ShowHelp { get; set; }

    public bool ShowVersion { get; set; }

    public List<string> Unreadable { get; } = [];

    public static ServerSettings Load(string[] args, IConfiguration? configuration = null)
    {
        var settings = new ServerSettings();

        // 1. Environment variables (RELAY_*)
        string? Env(string name)
        {
            var value = configuration?[name] ?? Environment.GetEnvironmentVariable(name);
            var trimmed = value?.Trim();
            return string.IsNullOrEmpty(trimmed) ? null : trimmed;
        }

        if (Env("RELAY_NAME") is { } envName) settings.ServerName = envName;
        if (Env("RELAY_OWNER_NAME") is { } envOwner) settings.OwnerName = envOwner;
        if (Env("RELAY_DATA_DIR") is { } envData) settings.DataDir = envData;
        if (Env("RELAY_LISTEN") is { } envListen) settings.ListenUrl = envListen;
        else if (Env("ASPNETCORE_URLS") is { } envAspNetUrls) settings.ListenUrl = envAspNetUrls;
        if (Env("RELAY_PUBLIC_URL") is { } envPublic) settings.ParsePublicUrl(envPublic, "RELAY_PUBLIC_URL");
        if (Env("RELAY_SECRET") is { } envSecret) settings.ParseSecret(envSecret, "RELAY_SECRET");
        if (Env("RELAY_PASSWORD") is { } envPassword) settings.Password = envPassword;
        if (Env("RELAY_ACCESS_KEY") is { } envKey) settings.AccessKey = envKey;
        if (Env("RELAY_TRUST_PROXY") is { } envTrust) settings.TrustProxy = ParseBool(envTrust);
        if (Env("RELAY_MAX_DEVICES") is { } envMaxDev) settings.MaxDevices = (int)settings.ParseNumber(envMaxDev, "RELAY_MAX_DEVICES", settings.MaxDevices, 1);
        if (Env("RELAY_MAX_HOSTS") is { } envMaxHosts) settings.Relay.MaxHosts = (int)settings.ParseNumber(envMaxHosts, "RELAY_MAX_HOSTS", settings.Relay.MaxHosts, 1);
        if (Env("RELAY_MAX_TUNNELS") is { } envMaxTunnels) settings.Relay.MaxTunnels = (int)settings.ParseNumber(envMaxTunnels, "RELAY_MAX_TUNNELS", settings.Relay.MaxTunnels, 1);
        if (Env("RELAY_MAX_TUNNELS_PER_HOST") is { } envMaxHostTunnels) settings.Relay.MaxTunnelsPerHost = (int)settings.ParseNumber(envMaxHostTunnels, "RELAY_MAX_TUNNELS_PER_HOST", settings.Relay.MaxTunnelsPerHost, 1);
        if (Env("RELAY_MONTHLY_BYTES") is { } envMonthly) settings.Relay.MonthlyBytesLimit = settings.ParseNumber(envMonthly, "RELAY_MONTHLY_BYTES", 0, 0, long.MaxValue);
        if (Env("RELAY_IDLE_SECONDS") is { } envIdle) settings.Relay.IdleTimeout = TimeSpan.FromSeconds(settings.ParseNumber(envIdle, "RELAY_IDLE_SECONDS", 0, 0));
        if (Env("RELAY_TLS_CERT") is { } envCert) settings.TlsCertPath = envCert;
        if (Env("RELAY_TLS_KEY") is { } envKeyPath) settings.TlsKeyPath = envKeyPath;
        if (Env("RELAY_STUN_PORT") is { } envStunPort) settings.StunPort = (int)settings.ParseNumber(envStunPort, "RELAY_STUN_PORT", 3478, 0, 65535);
        if (Env("RELAY_STUN_HOST") is { } envStunHost) settings.StunHost = envStunHost;
        if (Env("RELAY_STUN_BIND") is { } envStunBind) settings.StunBindAddress = settings.ParseIp(envStunBind, "RELAY_STUN_BIND");
        if (Env("RELAY_STUN_SERVERS") is { } envStunServers) settings.ParseStunServers(envStunServers);
        if (Env("RELAY_QUIC_PORT") is { } envQuicPort) settings.QuicPort = (int)settings.ParseNumber(envQuicPort, "RELAY_QUIC_PORT", 8443, 0, 65535);
        if (Env("RELAY_QUIC_HOST") is { } envQuicHost) settings.QuicHost = envQuicHost;
        if (Env("RELAY_QUIC_BIND") is { } envQuicBind) settings.QuicBindAddress = settings.ParseIp(envQuicBind, "RELAY_QUIC_BIND");

        // 2. Command-line flags override environment variables
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg is "-h" or "--help")
            {
                settings.ShowHelp = true;
                continue;
            }

            if (arg is "-v" or "--version")
            {
                settings.ShowVersion = true;
                continue;
            }

            string key;
            string? inlineValue = null;
            var eq = arg.IndexOf('=');
            if (eq > 0 && arg.StartsWith("--", StringComparison.Ordinal))
            {
                key = arg[..eq];
                inlineValue = arg[(eq + 1)..];
            }
            else
            {
                key = arg;
            }

            string? NextValue()
            {
                if (inlineValue is not null)
                {
                    return inlineValue;
                }

                if (i + 1 < args.Length)
                {
                    return args[++i];
                }

                settings.Unreadable.Add($"Missing value for {key}.");
                return null;
            }

            switch (key)
            {
                case "--data":
                    if (NextValue() is { } data) settings.DataDir = data;
                    break;
                case "--listen":
                    if (NextValue() is { } listen) settings.ListenUrl = listen;
                    break;
                case "--public-url":
                    if (NextValue() is { } pub) settings.ParsePublicUrl(pub, "--public-url");
                    break;
                case "--secret":
                    if (NextValue() is { } sec) settings.ParseSecret(sec, "--secret");
                    break;
                case "--password":
                    if (NextValue() is { } pwd) settings.Password = pwd;
                    break;
                case "--access-key":
                    if (NextValue() is { } akey) settings.AccessKey = akey;
                    break;
                case "--name":
                    if (NextValue() is { } sname && !string.IsNullOrWhiteSpace(sname)) settings.ServerName = sname.Trim();
                    break;
                case "--owner":
                    if (NextValue() is { } owner && !string.IsNullOrWhiteSpace(owner)) settings.OwnerName = owner.Trim();
                    break;
                case "--trust-proxy":
                    settings.TrustProxy = inlineValue is null || ParseBool(inlineValue);
                    break;
                case "--tls-cert":
                    if (NextValue() is { } cert) settings.TlsCertPath = cert;
                    break;
                case "--tls-key":
                    if (NextValue() is { } tlsKey) settings.TlsKeyPath = tlsKey;
                    break;
                case "--stun-port":
                    if (NextValue() is { } sp) settings.StunPort = (int)settings.ParseNumber(sp, "--stun-port", 3478, 0, 65535);
                    break;
                case "--stun-host":
                    if (NextValue() is { } sh) settings.StunHost = sh.Trim();
                    break;
                case "--stun-bind":
                    if (NextValue() is { } sb) settings.StunBindAddress = settings.ParseIp(sb, "--stun-bind");
                    break;
                case "--stun-servers":
                    if (NextValue() is { } ss) settings.ParseStunServers(ss);
                    break;
                case "--quic-port":
                    if (NextValue() is { } qp) settings.QuicPort = (int)settings.ParseNumber(qp, "--quic-port", 8443, 0, 65535);
                    break;
                case "--quic-host":
                    if (NextValue() is { } qh) settings.QuicHost = qh.Trim();
                    break;
                case "--quic-bind":
                    if (NextValue() is { } qb) settings.QuicBindAddress = settings.ParseIp(qb, "--quic-bind");
                    break;
                case "--memory":
                    settings.DataDir = null;
                    break;
                default:
                    settings.Unreadable.Add($"Unknown argument: {arg}");
                    break;
            }
        }

        return settings;
    }

    public (IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings) Check()
    {
        var errors = new List<string>(Unreadable);
        var warnings = new List<string>();

        if (Secret is { Length: < 32 })
        {
            errors.Add("RELAY_SECRET must decode to at least 32 bytes. Generate one with: openssl rand -base64 48");
        }

        if (Password is not null && Password.Length < OwnerAuthService.MinPasswordLength)
        {
            errors.Add($"RELAY_PASSWORD must be at least {OwnerAuthService.MinPasswordLength} characters long.");
        }

        if (AccessKey is not null && AccessKey.Length < OwnerAuthService.MinAccessKeyLength)
        {
            errors.Add($"RELAY_ACCESS_KEY must be at least {OwnerAuthService.MinAccessKeyLength} characters long.");
        }

        if (string.IsNullOrWhiteSpace(TlsCertPath) != string.IsNullOrWhiteSpace(TlsKeyPath))
        {
            errors.Add("RELAY_TLS_CERT and RELAY_TLS_KEY must be set together.");
        }
        else if (!string.IsNullOrWhiteSpace(TlsCertPath))
        {
            if (!File.Exists(TlsCertPath))
            {
                errors.Add($"RELAY_TLS_CERT file does not exist: {TlsCertPath}");
            }

            if (!File.Exists(TlsKeyPath))
            {
                errors.Add($"RELAY_TLS_KEY file does not exist: {TlsKeyPath}");
            }
        }

        if (DataDir is null)
        {
            warnings.Add("Running in memory-only mode: authorized devices will be signed out after restart.");
        }

        if (PublicUrl is { Scheme: "http", IsLoopback: false })
        {
            warnings.Add("RELAY_PUBLIC_URL uses plain http://; mobile apps and browsers require https:// over the internet.");
        }

        return (errors, warnings);
    }

    private void ParsePublicUrl(string raw, string source)
    {
        if (Uri.TryCreate(raw, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) && !string.IsNullOrEmpty(uri.Host))
        {
            PublicUrl = new Uri(uri.GetLeftPart(UriPartial.Authority));
            return;
        }

        Unreadable.Add($"{source} is not a valid http(s) URL.");
    }

    private void ParseSecret(string raw, string source)
    {
        try
        {
            Secret = Convert.FromBase64String(raw);
        }
        catch (FormatException)
        {
            Unreadable.Add($"{source} is not valid base64.");
        }
    }

    private long ParseNumber(string raw, string source, long fallback, long min, long max = int.MaxValue)
    {
        if (long.TryParse(raw, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var number)
            && number >= min && number <= max)
        {
            return number;
        }

        Unreadable.Add($"{source} must be an integer >= {min}.");
        return fallback;
    }

    private static bool ParseBool(string value)
    {
        return value is "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    private IPAddress? ParseIp(string raw, string source)
    {
        if (IPAddress.TryParse(raw.Trim(), out var ip))
        {
            return ip;
        }

        Unreadable.Add($"{source} is not a valid IP address.");
        return null;
    }

    private void ParseStunServers(string raw)
    {
        foreach (var entry in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (entry.Length == 0 || entry.Length > 255 || entry.Any(char.IsControl))
            {
                continue;
            }

            var normalized = entry.StartsWith("stun:", StringComparison.OrdinalIgnoreCase) ? entry : $"stun:{entry}";
            if (!ExternalStunServers.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                ExternalStunServers.Add(normalized);
            }
        }
    }
}
