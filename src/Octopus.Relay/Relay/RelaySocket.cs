using System.Buffers;
using System.Buffers.Binary;
using System.Net.Quic;
using System.Net.WebSockets;
using System.Runtime.Versioning;

namespace Octopus.Relay.Relay;

/// <summary>One end of a relay tunnel (either a WebSocket or a length-prefixed QUIC stream).</summary>
internal interface ITunnelEnd
{
    Task CloseAsync(WebSocketCloseStatus status, string description, bool drain);

    void Abort();
}

/// <summary>Serializes writes and close frames on a single WebSocket.</summary>
internal sealed class RelaySocket(WebSocket socket) : ITunnelEnd
{
    internal static readonly TimeSpan CloseGrace = TimeSpan.FromSeconds(2);

    private readonly SemaphoreSlim _send = new(1, 1);
    private volatile bool _closing;

    public WebSocket Socket => socket;

    public async ValueTask<bool> SendAsync(ReadOnlyMemory<byte> data, WebSocketMessageType type, bool endOfMessage, CancellationToken cancellationToken)
    {
        await _send.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_closing || socket.State != WebSocketState.Open)
            {
                return false;
            }

            await socket.SendAsync(data, type, endOfMessage, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _send.Release();
        }
    }

    public async Task CloseAsync(WebSocketCloseStatus status, string description, bool drain)
    {
        _closing = true;
        try
        {
            using var timeout = new CancellationTokenSource(CloseGrace);
            await _send.WaitAsync(timeout.Token).ConfigureAwait(false);
            try
            {
                if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
                {
                    if (drain && socket.State == WebSocketState.Open)
                    {
                        await socket.CloseAsync(status, description, timeout.Token).ConfigureAwait(false);
                    }
                    else
                    {
                        await socket.CloseOutputAsync(status, description, timeout.Token).ConfigureAwait(false);
                    }
                }
            }
            finally
            {
                _send.Release();
            }
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException or ObjectDisposedException or IOException or InvalidOperationException)
        {
            Abort();
        }
    }

    public void Abort()
    {
        try
        {
            socket.Abort();
        }
        catch (ObjectDisposedException)
        {
        }
    }
}

/// <summary>
/// A bidirectional QUIC stream end of a relay tunnel, speaking 4-byte little-endian length-prefixed messages
/// matching <c>Octopus.Remote.Transport.FramedStreamTransport</c>.
/// </summary>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("macos")]
internal sealed class QuicTunnelEnd(QuicConnection connection, QuicStream stream) : ITunnelEnd
{
    internal const int MaxMessageBytes = 2 * 1024 * 1024;
    private readonly SemaphoreSlim _send = new(1, 1);
    private volatile bool _closing;

    public QuicStream Stream => stream;

    public async ValueTask<bool> WriteRawAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await _send.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_closing)
            {
                return false;
            }

            await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _send.Release();
        }
    }

    public async ValueTask<bool> WriteFramedMessageAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        await _send.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_closing)
            {
                return false;
            }

            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            if (!payload.IsEmpty)
            {
                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            }

            return true;
        }
        finally
        {
            _send.Release();
        }
    }

    public static async ValueTask<byte[]?> ReadFramedMessageAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length < 0 || length > maxBytes)
        {
            throw new IOException($"QUIC tunnel message length {length} is out of bounds.");
        }

        if (length == 0)
        {
            return [];
        }

        var payload = new byte[length];
        if (!await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        return payload;
    }

    public static async ValueTask WriteFramedAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        var header = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
            await stream.WriteAsync(header.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
            if (!payload.IsEmpty)
            {
                await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }
    }

    private static async ValueTask<bool> ReadExactAsync(Stream stream, Memory<byte> destination, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    public async Task CloseAsync(WebSocketCloseStatus status, string description, bool drain)
    {
        _closing = true;
        try
        {
            stream.CompleteWrites();
        }
        catch (Exception)
        {
        }

        try
        {
            var code = status == WebSocketCloseStatus.NormalClosure ? 0L : (long)status;
            using var timeout = new CancellationTokenSource(RelaySocket.CloseGrace);
            await connection.CloseAsync(code, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }

        await DisposeQuietlyAsync().ConfigureAwait(false);
    }

    public void Abort()
    {
        _closing = true;
        try
        {
            stream.Abort(QuicAbortDirection.Both, 0x0A);
        }
        catch (Exception)
        {
        }

        _ = DisposeQuietlyAsync();
    }

    private async Task DisposeQuietlyAsync()
    {
        try
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
        }

        try
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
    }
}
