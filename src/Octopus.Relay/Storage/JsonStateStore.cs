using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Octopus.Relay.Auth;

namespace Octopus.Relay.Storage;

public enum RegisterDeviceStatus
{
    Added,
    Replaced,
    LimitReached,
}

/// <summary>
/// Pure BCL single-file atomic JSON persistence for single-owner state (<c>state.json</c>) and auto-generated server
/// secret (<c>secret.key</c>). Zero external databases or native dependencies.
/// </summary>
public sealed class JsonStateStore : IDisposable
{
    private const int SecretByteLength = 48;
    private static readonly TimeSpan UsageFlushInterval = TimeSpan.FromSeconds(30);

    private readonly string? _dataDirectory;
    private readonly string? _statePath;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private readonly Timer? _usageTimer;

    private RelayStateDocument _state = new();
    private bool _usageDirty;
    private bool _disposed;

    /// <param name="dataDirectory">Directory for <c>state.json</c> and <c>secret.key</c>. Null runs purely in memory (tests).</param>
    public JsonStateStore(string? dataDirectory, TimeProvider time, string defaultOwnerName = "Owner")
    {
        _dataDirectory = string.IsNullOrWhiteSpace(dataDirectory) ? null : Path.GetFullPath(dataDirectory);
        _statePath = _dataDirectory is null ? null : Path.Combine(_dataDirectory, "state.json");
        _time = time;
        _state = LoadOrCreate(defaultOwnerName);
        if (_statePath is not null)
        {
            _usageTimer = new Timer(_ => FlushUsageIfDirty(), null, UsageFlushInterval, UsageFlushInterval);
        }
    }

    public string? DataDirectory => _dataDirectory;

    /// <summary>Loads an existing <c>secret.key</c> from <paramref name="dataDirectory"/> or generates and saves one.</summary>
    public static byte[] LoadOrCreateSecret(string? dataDirectory)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            return RandomNumberGenerator.GetBytes(SecretByteLength);
        }

        var dir = Path.GetFullPath(dataDirectory);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "secret.key");
        if (File.Exists(path))
        {
            var text = File.ReadAllText(path, Encoding.UTF8).Trim();
            var bytes = Convert.FromBase64String(text);
            if (bytes.Length < 32)
            {
                throw new InvalidOperationException($"The secret file {path} is shorter than 32 bytes.");
            }

            return bytes;
        }

        var generated = RandomNumberGenerator.GetBytes(SecretByteLength);
        WriteAtomicText(path, Convert.ToBase64String(generated) + "\n");
        return generated;
    }

    public OwnerProfile GetOwner()
    {
        lock (_gate)
        {
            return CloneOwner(_state.Owner);
        }
    }

    public OwnerProfile UpdateOwner(Action<OwnerProfile> mutate)
    {
        lock (_gate)
        {
            mutate(_state.Owner);
            PersistLocked();
            return CloneOwner(_state.Owner);
        }
    }

    public DeviceRecord? GetDevice(string deviceId)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            var device = _state.Devices.FirstOrDefault(d => d.Id == deviceId);
            if (device is null || device.ExpiresAt <= now)
            {
                return null;
            }

            return device.Clone();
        }
    }

    public IReadOnlyList<DeviceRecord> GetDevices()
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            return
            [
                .. _state.Devices
                    .Where(d => d.ExpiresAt > now)
                    .OrderByDescending(d => d.LastSeenAt)
                    .Select(d => d.Clone()),
            ];
        }
    }

    public RegisterDeviceStatus RegisterDevice(DeviceRecord device, int maxDevices)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            _state.Devices.RemoveAll(d => d.ExpiresAt <= now);
            var existingIndex = _state.Devices.FindIndex(d => d.Id == device.Id);
            if (existingIndex >= 0)
            {
                _state.Devices[existingIndex] = device.Clone();
                PersistLocked();
                return RegisterDeviceStatus.Replaced;
            }

            if (maxDevices > 0 && _state.Devices.Count >= maxDevices)
            {
                return RegisterDeviceStatus.LimitReached;
            }

            _state.Devices.Add(device.Clone());
            PersistLocked();
            return RegisterDeviceStatus.Added;
        }
    }

    public bool RotateRefresh(string deviceId, string expectedHash, bool expectedIsCurrent, string newHash, DateTimeOffset now, DateTimeOffset expiresAt, string? ip)
    {
        lock (_gate)
        {
            var device = _state.Devices.FirstOrDefault(d => d.Id == deviceId);
            if (device is null || device.ExpiresAt <= now)
            {
                return false;
            }

            if (expectedIsCurrent)
            {
                if (!string.Equals(device.RefreshHash, expectedHash, StringComparison.Ordinal))
                {
                    return false;
                }

                device.PreviousRefreshHash = device.RefreshHash;
                device.RefreshHash = newHash;
                device.RotatedAt = now;
            }
            else
            {
                if (!string.Equals(device.PreviousRefreshHash, expectedHash, StringComparison.Ordinal))
                {
                    return false;
                }

                device.RefreshHash = newHash;
            }

            device.LastSeenAt = now;
            device.ExpiresAt = expiresAt;
            if (ip is not null)
            {
                device.LastIp = ip;
            }

            PersistLocked();
            return true;
        }
    }

    public void TouchDevice(string deviceId, string? name, string? ip, DateTimeOffset now)
    {
        lock (_gate)
        {
            var device = _state.Devices.FirstOrDefault(d => d.Id == deviceId);
            if (device is null || device.ExpiresAt <= now)
            {
                return;
            }

            var changed = false;
            if (name is not null && !string.Equals(device.Name, name, StringComparison.Ordinal))
            {
                device.Name = name;
                changed = true;
            }

            if (ip is not null && !string.Equals(device.LastIp, ip, StringComparison.Ordinal))
            {
                device.LastIp = ip;
                changed = true;
            }

            if (now - device.LastSeenAt >= TimeSpan.FromMinutes(1))
            {
                device.LastSeenAt = now;
                changed = true;
            }

            if (changed)
            {
                PersistLocked();
            }
        }
    }

    public bool DeleteDevice(string deviceId)
    {
        lock (_gate)
        {
            var removed = _state.Devices.RemoveAll(d => d.Id == deviceId) > 0;
            if (removed)
            {
                PersistLocked();
            }

            return removed;
        }
    }

    public IReadOnlyList<string> DeleteAllDevices()
    {
        lock (_gate)
        {
            var ids = _state.Devices.Select(d => d.Id).ToList();
            if (ids.Count > 0)
            {
                _state.Devices.Clear();
                PersistLocked();
            }

            return ids;
        }
    }

    public void AddWebSession(WebSessionRecord session)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            _state.WebSessions.RemoveAll(s => s.ExpiresAt <= now);
            _state.WebSessions.Add(session);
            // Bound stored web sessions to avoid unbounded file growth.
            if (_state.WebSessions.Count > 32)
            {
                _state.WebSessions.Sort((a, b) => b.LastSeenAt.CompareTo(a.LastSeenAt));
                _state.WebSessions.RemoveRange(32, _state.WebSessions.Count - 32);
            }

            PersistLocked();
        }
    }

    public WebSessionRecord? GetWebSession(string tokenHash)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            var session = _state.WebSessions.FirstOrDefault(s => string.Equals(s.TokenHash, tokenHash, StringComparison.Ordinal));
            if (session is null || session.ExpiresAt <= now)
            {
                return null;
            }

            return new WebSessionRecord
            {
                TokenHash = session.TokenHash,
                CreatedAt = session.CreatedAt,
                LastSeenAt = session.LastSeenAt,
                ExpiresAt = session.ExpiresAt,
                UserAgent = session.UserAgent,
                Ip = session.Ip,
            };
        }
    }

    public void TouchWebSession(string tokenHash, DateTimeOffset lastSeenAt, DateTimeOffset expiresAt)
    {
        lock (_gate)
        {
            var session = _state.WebSessions.FirstOrDefault(s => string.Equals(s.TokenHash, tokenHash, StringComparison.Ordinal));
            if (session is null)
            {
                return;
            }

            session.LastSeenAt = lastSeenAt;
            session.ExpiresAt = expiresAt;
            PersistLocked();
        }
    }

    public void DeleteWebSession(string tokenHash)
    {
        lock (_gate)
        {
            if (_state.WebSessions.RemoveAll(s => string.Equals(s.TokenHash, tokenHash, StringComparison.Ordinal)) > 0)
            {
                PersistLocked();
            }
        }
    }

    public void DeleteAllWebSessions()
    {
        lock (_gate)
        {
            if (_state.WebSessions.Count > 0)
            {
                _state.WebSessions.Clear();
                PersistLocked();
            }
        }
    }

    public long GetUsage(string month)
    {
        lock (_gate)
        {
            return _state.UsageByMonth.TryGetValue(month, out var total) ? total : 0;
        }
    }

    public long AddUsage(string month, long bytes)
    {
        lock (_gate)
        {
            var total = (_state.UsageByMonth.TryGetValue(month, out var existing) ? existing : 0) + bytes;
            _state.UsageByMonth[month] = total;
            _usageDirty = true;
            return total;
        }
    }

    public void Flush()
    {
        lock (_gate)
        {
            if (_usageDirty)
            {
                PersistLocked();
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _usageTimer?.Dispose();
        Flush();
    }

    private void FlushUsageIfDirty()
    {
        try
        {
            Flush();
        }
        catch (Exception)
        {
            // Next write or shutdown retries.
        }
    }

    private RelayStateDocument LoadOrCreate(string defaultOwnerName)
    {
        if (_statePath is not null && File.Exists(_statePath))
        {
            var bytes = File.ReadAllBytes(_statePath);
            var loaded = JsonSerializer.Deserialize(bytes, StateJsonContext.Default.RelayStateDocument)
                ?? throw new InvalidOperationException($"State file {_statePath} is empty or invalid JSON.");
            if (string.IsNullOrWhiteSpace(loaded.Owner.Id))
            {
                loaded.Owner.Id = Secrets.NewAccountId();
            }

            if (string.IsNullOrWhiteSpace(loaded.Owner.Name))
            {
                loaded.Owner.Name = defaultOwnerName;
            }

            if (loaded.Owner.CreatedAt == default)
            {
                loaded.Owner.CreatedAt = _time.GetUtcNow();
            }

            loaded.Devices ??= [];
            loaded.WebSessions ??= [];
            loaded.UsageByMonth ??= new(StringComparer.Ordinal);
            return loaded;
        }

        var fresh = new RelayStateDocument
        {
            Schema = 1,
            Owner = new OwnerProfile
            {
                Id = Secrets.NewAccountId(),
                Name = defaultOwnerName,
                CreatedAt = _time.GetUtcNow(),
            },
        };

        if (_statePath is not null)
        {
            _state = fresh;
            PersistLocked();
        }

        return fresh;
    }

    private void PersistLocked()
    {
        _usageDirty = false;
        if (_statePath is null)
        {
            return;
        }

        var json = JsonSerializer.SerializeToUtf8Bytes(_state, StateJsonContext.Default.RelayStateDocument);
        WriteAtomicBytes(_statePath, json);
    }

    private static OwnerProfile CloneOwner(OwnerProfile owner) => new()
    {
        Id = owner.Id,
        Name = owner.Name,
        PasswordHash = owner.PasswordHash,
        AccessKeyHash = owner.AccessKeyHash,
        AccessKeyHint = owner.AccessKeyHint,
        CreatedAt = owner.CreatedAt,
    };

    private static void WriteAtomicText(string path, string content)
    {
        WriteAtomicBytes(path, Encoding.UTF8.GetBytes(content));
    }

    private static void WriteAtomicBytes(string path, ReadOnlySpan<byte> content)
    {
        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        var temp = path + "." + RandomNumberGenerator.GetHexString(8, lowercase: true) + ".tmp";
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var stream = new FileStream(temp, options))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, path, overwrite: true);
        }
        catch
        {
            try
            {
                if (File.Exists(temp))
                {
                    File.Delete(temp);
                }
            }
            catch (IOException)
            {
            }

            throw;
        }
    }
}
