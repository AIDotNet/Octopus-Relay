using System.Globalization;
using Octopus.Relay.Auth;
using Octopus.Relay.Relay;
using Octopus.Relay.Storage;

namespace Octopus.Relay.Api;

internal sealed class RelayUsage(JsonStateStore store, TimeProvider time) : IRelayUsage
{
    public ValueTask<long> GetAsync(CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(store.GetUsage(Month()));
    }

    public ValueTask<long> AddAsync(long bytes, CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(store.AddUsage(Month(), bytes));
    }

    public string CurrentMonth() => Month();

    private string Month() => time.GetUtcNow().ToString("yyyy-MM", CultureInfo.InvariantCulture);
}

internal sealed class RelaySignOut(RelayHub relay) : IDeviceSignOut
{
    public void SignedOut(string deviceId)
    {
        _ = relay.KickAsync(deviceId);
    }
}
