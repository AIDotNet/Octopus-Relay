using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Octopus.Relay.Api;
using Octopus.Relay.Auth;
using Octopus.Relay.Storage;

namespace Octopus.Relay.Relay;

/// <summary>
/// Optional QUIC tunnel endpoint (<c>ALPN: octopus-relay-v2</c>) allowing QUIC-capable hosts and clients
/// to join relay tunnels over UDP with zero TCP head-of-line blocking, and seamlessly bridge with WebSocket peers.
/// </summary>
public sealed class QuicRelayServer(
    ServerSettings settings,
    JsonStateStore store,
    AccessTokens accessTokens,
    RelayHub relay,
    ILogger<QuicRelayServer> logger) : IHostedService, IAsyncDisposable
{
    public static readonly SslApplicationProtocol ApplicationProtocol = new("octopus-relay-v2");
    private const int MaxJoinBytes = 4096;
    private static readonly TimeSpan JoinTimeout = TimeSpan.FromSeconds(10);

    private QuicListener? _listener;
    private X509Certificate2? _certificate;
    private bool _ownsCertificate;
    private CancellationTokenSource? _stop;
    private Task? _loop;
    private int? _boundPort;

    public bool IsRunning => _boundPort is not null;

    public int? BoundPort => _boundPort;

    public static bool IsSupported =>
        (OperatingSystem.IsLinux() || OperatingSystem.IsWindows() || OperatingSystem.IsMacOS())
        && IsQuicListenerSupported();

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private static bool IsQuicListenerSupported() => QuicListener.IsSupported;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (settings.QuicPort is not { } port)
        {
            return;
        }

        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()))
        {
            logger.LogWarning("QUIC relay listener requested on port {Port}, but this OS does not support System.Net.Quic; continuing with WebSocket only.", port);
            return;
        }

        await StartCoreAsync(port, cancellationToken).ConfigureAwait(false);
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private async Task StartCoreAsync(int port, CancellationToken cancellationToken)
    {
        if (!QuicListener.IsSupported)
        {
            logger.LogWarning("QUIC relay listener requested on port {Port}, but libmsquic is not available; continuing with WebSocket only.", port);
            return;
        }

        if (!string.IsNullOrWhiteSpace(settings.TlsCertPath) && !string.IsNullOrWhiteSpace(settings.TlsKeyPath))
        {
            _certificate = X509Certificate2.CreateFromPemFile(settings.TlsCertPath, settings.TlsKeyPath);
            _ownsCertificate = true;
        }
        else
        {
            _certificate = CreateEphemeralCertificate();
            _ownsCertificate = true;
        }

        var bind = settings.QuicBindAddress ?? IPAddress.Any;
        var idle = settings.Relay.IdleTimeout > TimeSpan.Zero ? settings.Relay.IdleTimeout : TimeSpan.FromSeconds(60);
        var serverOptions = new QuicServerConnectionOptions
        {
            DefaultStreamErrorCode = 0x0A,
            DefaultCloseErrorCode = 0x0B,
            MaxInboundBidirectionalStreams = 4,
            MaxInboundUnidirectionalStreams = 1,
            IdleTimeout = idle,
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [ApplicationProtocol],
                ServerCertificate = _certificate,
                ClientCertificateRequired = false,
            },
        };

        _listener = await QuicListener.ListenAsync(new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(bind, port),
            ApplicationProtocols = [ApplicationProtocol],
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        }, cancellationToken).ConfigureAwait(false);

        _boundPort = _listener.LocalEndPoint.Port;
        _stop = new CancellationTokenSource();
        _loop = Task.Run(() => AcceptLoopAsync(_listener, _stop.Token));
        logger.LogInformation("QUIC relay server listening on quic://{Address}:{Port} (ALPN: {Alpn})", bind, _boundPort, ApplicationProtocol);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        var stop = _stop;
        var loop = _loop;
        _stop = null;
        _loop = null;
        _boundPort = null;

        if (stop is not null)
        {
            await stop.CancelAsync().ConfigureAwait(false);
        }

        if ((OperatingSystem.IsLinux() || OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()) && _listener is not null)
        {
            await DisposeListenerCoreAsync().ConfigureAwait(false);
        }

        if (loop is not null)
        {
            try
            {
                await loop.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        if (_ownsCertificate)
        {
            _certificate?.Dispose();
            _certificate = null;
            _ownsCertificate = false;
        }

        stop?.Dispose();
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private async ValueTask DisposeListenerCoreAsync()
    {
        if (_listener is { } listener)
        {
            _listener = null;
            try
            {
                await listener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }
    }

    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));

    /// <summary>Returns the <c>quic://host:port</c> URI advertised in <c>/v1/info</c>, or null when QUIC is inactive.</summary>
    public string? AdvertisedEndpoint(Uri publicOrigin)
    {
        if (_boundPort is not { } port)
        {
            return null;
        }

        var host = !string.IsNullOrWhiteSpace(settings.QuicHost) ? settings.QuicHost!.Trim() : publicOrigin.Host;
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        if (host.Contains(':', StringComparison.Ordinal) && !host.StartsWith('['))
        {
            host = $"[{host}]";
        }

        return $"quic://{host}:{port}";
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private async Task AcceptLoopAsync(QuicListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            QuicConnection connection;
            try
            {
                connection = await listener.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (e is OperationCanceledException or QuicException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = Task.Run(() => HandleConnectionAsync(connection, cancellationToken));
        }
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private async Task HandleConnectionAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        QuicStream? stream = null;
        var handedOff = false;
        try
        {
            using var joinLimit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            joinLimit.CancelAfter(JoinTimeout);

            stream = await connection.AcceptInboundStreamAsync(joinLimit.Token).ConfigureAwait(false);
            var raw = await QuicTunnelEnd.ReadFramedMessageAsync(stream, MaxJoinBytes, joinLimit.Token).ConfigureAwait(false);
            if (raw is null)
            {
                return;
            }

            QuicTunnelJoinRequest? request;
            try
            {
                request = JsonSerializer.Deserialize(raw, ApiJson.Default.QuicTunnelJoinRequest);
            }
            catch (JsonException)
            {
                await SendJoinResultAsync(stream, ok: false, "invalid_request", joinLimit.Token).ConfigureAwait(false);
                return;
            }

            if (request is null || string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.Tunnel))
            {
                await SendJoinResultAsync(stream, ok: false, "invalid_request", joinLimit.Token).ConfigureAwait(false);
                return;
            }

            if (!accessTokens.TryValidate(request.Token.Trim(), out var grant) || grant.AccountId != store.GetOwner().Id)
            {
                await SendJoinResultAsync(stream, ok: false, "unauthorized", joinLimit.Token).ConfigureAwait(false);
                return;
            }

            TunnelRole role;
            switch (request.Role)
            {
                case "host":
                    role = TunnelRole.Host;
                    break;
                case "device":
                    role = TunnelRole.Device;
                    break;
                default:
                    await SendJoinResultAsync(stream, ok: false, "invalid_request", joinLimit.Token).ConfigureAwait(false);
                    return;
            }

            switch (relay.Join(request.Tunnel, grant.AccountId, grant.DeviceId, role, out var seat))
            {
                case TunnelJoinStatus.NotFound:
                    await SendJoinResultAsync(stream, ok: false, "not_found", joinLimit.Token).ConfigureAwait(false);
                    return;
                case TunnelJoinStatus.Forbidden:
                    await SendJoinResultAsync(stream, ok: false, "forbidden", joinLimit.Token).ConfigureAwait(false);
                    return;
                case TunnelJoinStatus.Taken:
                    await SendJoinResultAsync(stream, ok: false, "conflict", joinLimit.Token).ConfigureAwait(false);
                    return;
            }

            try
            {
                await SendJoinResultAsync(stream, ok: true, error: null, joinLimit.Token).ConfigureAwait(false);
            }
            catch
            {
                relay.Abandon(seat!);
                throw;
            }

            handedOff = true;
            var end = new QuicTunnelEnd(connection, stream);
            await relay.RunTunnelAsync(seat!, end, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is OperationCanceledException or QuicException or IOException or ObjectDisposedException)
        {
        }
        finally
        {
            if (!handedOff)
            {
                if (stream is not null)
                {
                    try { await stream.DisposeAsync().ConfigureAwait(false); } catch { }
                }

                try { await connection.DisposeAsync().ConfigureAwait(false); } catch { }
            }
        }
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("macos")]
    private static async Task SendJoinResultAsync(QuicStream stream, bool ok, string? error, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new QuicTunnelJoinResponse(ok, error), ApiJson.Default.QuicTunnelJoinResponse);
        await QuicTunnelEnd.WriteFramedAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
    }

    private static X509Certificate2 CreateEphemeralCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=octopus-relay-quic", key, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }
}
