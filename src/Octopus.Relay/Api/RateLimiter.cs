namespace Octopus.Relay.Api;

/// <summary>Per-IP, per-endpoint-group 1-minute request rate limiter.</summary>
internal sealed class RateLimiter(TimeProvider time)
{
    private readonly Lock _gate = new();
    private readonly Dictionary<(string Group, string Address), (long Minute, int Count)> _windows = [];
    private long _sweptMinute;

    public bool Allow(string group, string address, int limit, out int retryAfter)
    {
        var now = time.GetUtcNow();
        var minute = now.ToUnixTimeSeconds() / 60;
        retryAfter = (int)(60 - (now.ToUnixTimeSeconds() % 60));
        lock (_gate)
        {
            if (minute != _sweptMinute)
            {
                _sweptMinute = minute;
                foreach (var key in _windows.Where(w => w.Value.Minute != minute).Select(w => w.Key).ToList())
                {
                    _windows.Remove(key);
                }
            }

            var count = _windows.TryGetValue((group, address), out var window) && window.Minute == minute ? window.Count : 0;
            if (count >= limit)
            {
                return false;
            }

            _windows[(group, address)] = (minute, count + 1);
            return true;
        }
    }
}
