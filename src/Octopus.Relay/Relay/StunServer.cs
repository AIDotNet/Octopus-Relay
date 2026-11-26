using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Octopus.Relay.Api;

namespace Octopus.Relay.Relay;

/// <summary>
/// Built-in lightweight RFC 5389 UDP STUN server (Binding Request -> Binding Success Response with
/// <c>XOR-MAPPED-ADDRESS</c>) enabling internet WebRTC P2P NAT traversal without external STUN dependencies.
/// </summary>
public sealed class StunServer(ServerSettings settings, ILogger<StunServer> logger) : IHostedService, IAsyncDisposable
{
    public const uint MagicCookie = 0x2112A442;
    private const ushort BindingRequestType = 0x0001;
    private const ushort BindingResponseType = 0x0101;
    private const ushort AttrXorMappedAddress = 0x0020;
    private const int MaxDatagramBytes = 2048;

    private Socket? _socket;
    private CancellationTokenSource? _stop;
    private Task? _loop;
    private int? _boundPort;

    public bool IsRunning => _boundPort is not null;

    public int? BoundPort => _boundPort;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (settings.StunPort is not { } port)
        {
            return Task.CompletedTask;
        }

        var bind = settings.StunBindAddress ?? IPAddress.Any;
        var socket = new Socket(bind.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            if (bind.Equals(IPAddress.IPv6Any))
            {
                socket.DualMode = true;
            }

            socket.Bind(new IPEndPoint(bind, port));
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        _socket = socket;
        _boundPort = ((IPEndPoint)socket.LocalEndPoint!).Port;
        _stop = new CancellationTokenSource();
        _loop = Task.Run(() => ReceiveLoopAsync(socket, _stop.Token));
        logger.LogInformation("STUN server listening on udp://{Address}:{Port}", bind, _boundPort);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        var stop = _stop;
        var socket = _socket;
        var loop = _loop;
        _stop = null;
        _socket = null;
        _loop = null;
        _boundPort = null;

        if (stop is not null)
        {
            await stop.CancelAsync().ConfigureAwait(false);
        }

        socket?.Dispose();

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

        stop?.Dispose();
    }

    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));

    /// <summary>Returns the <c>stun:host:port</c> URI advertised in <c>/v1/info</c>, or null when STUN is disabled.</summary>
    public string? AdvertisedEndpoint(Uri publicOrigin)
    {
        if (_boundPort is not { } port)
        {
            return null;
        }

        var host = !string.IsNullOrWhiteSpace(settings.StunHost) ? settings.StunHost!.Trim() : publicOrigin.Host;
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        if (host.Contains(':', StringComparison.Ordinal) && !host.StartsWith('['))
        {
            host = $"[{host}]";
        }

        return $"stun:{host}:{port}";
    }

    /// <summary>
    /// Validates an RFC 5389 STUN Binding Request and builds a Binding Success Response encoding
    /// <paramref name="remote"/> in <c>XOR-MAPPED-ADDRESS</c>. Returns null for invalid or non-STUN packets.
    /// </summary>
    public static byte[]? TryBuildBindingResponse(ReadOnlySpan<byte> request, IPEndPoint remote)
    {
        if (request.Length < 20)
        {
            return null;
        }

        var messageType = BinaryPrimitives.ReadUInt16BigEndian(request[..2]);
        if (messageType != BindingRequestType)
        {
            return null;
        }

        var messageLength = BinaryPrimitives.ReadUInt16BigEndian(request.Slice(2, 2));
        if ((messageLength & 0x03) != 0 || 20 + messageLength > request.Length)
        {
            return null;
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(request.Slice(4, 4)) != MagicCookie)
        {
            return null;
        }

        var ip = remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address;
        var isV6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        var addrBytes = ip.GetAddressBytes();
        var attrValueLen = 4 + addrBytes.Length;
        var packet = new byte[20 + 4 + attrValueLen];

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), BindingResponseType);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)(4 + attrValueLen));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), MagicCookie);
        request.Slice(8, 12).CopyTo(packet.AsSpan(8, 12));

        // Attribute: XOR-MAPPED-ADDRESS (0x0020)
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), AttrXorMappedAddress);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), (ushort)attrValueLen);
        packet[24] = 0;
        packet[25] = isV6 ? (byte)0x02 : (byte)0x01;
        var xPort = (ushort)(remote.Port ^ (int)(MagicCookie >> 16));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), xPort);
        for (var i = 0; i < addrBytes.Length; i++)
        {
            packet[28 + i] = (byte)(addrBytes[i] ^ packet[4 + i]);
        }

        return packet;
    }

    private async Task ReceiveLoopAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxDatagramBytes];
        EndPoint anyRemote = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, anyRemote, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                continue;
            }

            if (received.RemoteEndPoint is not IPEndPoint remote)
            {
                continue;
            }

            var response = TryBuildBindingResponse(buffer.AsSpan(0, received.ReceivedBytes), remote);
            if (response is null)
            {
                continue;
            }

            try
            {
                await socket.SendToAsync(response, SocketFlags.None, remote, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
            }
        }
    }
}
