namespace Octopus.Relay.Relay;

/// <summary>Two WebSockets joined for transparent encrypted binary forwarding.</summary>
internal sealed class Tunnel(string id, string accountId, string hostDeviceId, string deviceId)
{
    public string Id => id;

    public string AccountId => accountId;

    public string HostDeviceId => hostDeviceId;

    public string DeviceId => deviceId;

    public bool HostTaken;
    public bool DeviceTaken;
    public RelaySocket? Host;
    public RelaySocket? Device;
    public bool Paired;
    public bool Closed;

    public long PendingBytes;

    public long LastActivity = Environment.TickCount64;

    public CancellationTokenSource Lifetime { get; } = new();

    public TaskCompletionSource Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
}

internal sealed class HostConnection(string accountId, string deviceId, RelaySocket socket, string[] initialFeatures)
{
    private string[] _features = initialFeatures;

    public string AccountId => accountId;

    public string DeviceId => deviceId;

    public RelaySocket Socket => socket;

    public string[] Features
    {
        get => Volatile.Read(ref _features);
        set => Volatile.Write(ref _features, value);
    }

    public CancellationTokenSource Lifetime { get; } = new();

    public async Task CloseAsync(int code, string description)
    {
        await socket.CloseAsync((System.Net.WebSockets.WebSocketCloseStatus)code, description, drain: false).ConfigureAwait(false);
        Cancel(RelaySocket.CloseGrace);
    }

    public void Cancel(TimeSpan after)
    {
        try
        {
            Lifetime.CancelAfter(after);
        }
        catch (ObjectDisposedException)
        {
        }
    }
}
