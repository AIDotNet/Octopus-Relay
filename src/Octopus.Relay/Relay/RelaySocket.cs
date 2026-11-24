using System.Net.WebSockets;

namespace Octopus.Relay.Relay;

/// <summary>Serializes writes and close frames on a single WebSocket.</summary>
internal sealed class RelaySocket(WebSocket socket)
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
