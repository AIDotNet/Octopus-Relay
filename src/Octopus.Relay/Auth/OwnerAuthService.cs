using Octopus.Relay.Storage;

namespace Octopus.Relay.Auth;

/// <summary>
/// Single-owner credential manager. Supports environment-supplied password / access key, or interactive first-run
/// web setup protected by a one-time bootstrap token printed to stdout.
/// </summary>
public sealed class OwnerAuthService
{
    public const int MinPasswordLength = 8;
    public const int MinAccessKeyLength = 16;

    private readonly JsonStateStore _store;
    private readonly string? _envPassword;
    private readonly string? _envAccessKey;
    private readonly string? _envAccessKeyHint;
    private readonly string? _bootstrapToken;

    public OwnerAuthService(JsonStateStore store, string? envPassword, string? envAccessKey, string? envOwnerName)
    {
        _store = store;
        _envPassword = string.IsNullOrWhiteSpace(envPassword) ? null : envPassword;
        _envAccessKey = string.IsNullOrWhiteSpace(envAccessKey) ? null : envAccessKey;
        _envAccessKeyHint = _envAccessKey is null ? null : Secrets.AccessKeyHint(_envAccessKey);

        if (!string.IsNullOrWhiteSpace(envOwnerName))
        {
            var trimmed = ValidateName(envOwnerName);
            if (trimmed is not null && !string.Equals(store.GetOwner().Name, trimmed, StringComparison.Ordinal))
            {
                store.UpdateOwner(owner => owner.Name = trimmed);
            }
        }

        if (NeedsSetup)
        {
            _bootstrapToken = Secrets.RandomToken(16);
        }
    }

    public bool PasswordManagedByEnv => _envPassword is not null;

    public bool AccessKeyManagedByEnv => _envAccessKey is not null;

    public bool PasswordEnabled
    {
        get
        {
            if (_envPassword is not null)
            {
                return true;
            }

            return !string.IsNullOrEmpty(_store.GetOwner().PasswordHash);
        }
    }

    public bool AccessKeyEnabled
    {
        get
        {
            if (_envAccessKey is not null)
            {
                return true;
            }

            return !string.IsNullOrEmpty(_store.GetOwner().AccessKeyHash);
        }
    }

    /// <summary>True only when neither a password nor an access key has ever been configured.</summary>
    public bool NeedsSetup => !PasswordEnabled && !AccessKeyEnabled;

    /// <summary>One-time setup token generated when <see cref="NeedsSetup"/> is true at startup; null otherwise.</summary>
    public string? BootstrapSetupToken => NeedsSetup ? _bootstrapToken : null;

    public string? AccessKeyHint => _envAccessKeyHint ?? _store.GetOwner().AccessKeyHint;

    public IReadOnlyList<string> SupportedAuthMethods
    {
        get
        {
            var methods = new List<string>(2);
            if (PasswordEnabled)
            {
                methods.Add("device_code");
            }

            if (AccessKeyEnabled)
            {
                methods.Add("access_key");
            }

            return methods;
        }
    }

    public bool VerifyPassword(string? password)
    {
        if (string.IsNullOrEmpty(password) || password.Length > 256)
        {
            return false;
        }

        if (_envPassword is not null)
        {
            return Secrets.FixedTimeEqualsString(password, _envPassword);
        }

        var hash = _store.GetOwner().PasswordHash;
        return Secrets.VerifyPassword(password, hash);
    }

    public bool VerifyAccessKey(string? key)
    {
        if (string.IsNullOrEmpty(key) || key.Length > 256)
        {
            return false;
        }

        if (_envAccessKey is not null)
        {
            return Secrets.FixedTimeEqualsString(key, _envAccessKey);
        }

        var storedHash = _store.GetOwner().AccessKeyHash;
        return !string.IsNullOrEmpty(storedHash) && Secrets.FixedTimeEqualsString(Secrets.Sha256Hex(key), storedHash);
    }

    public (bool Ok, string? Error, string? GeneratedAccessKey) CompleteSetup(string? setupToken, string? ownerName, string? password, bool generateAccessKey)
    {
        if (!NeedsSetup)
        {
            return (false, "setup_completed", null);
        }

        if (_bootstrapToken is not null && (string.IsNullOrEmpty(setupToken) || !Secrets.FixedTimeEqualsString(setupToken.Trim(), _bootstrapToken)))
        {
            return (false, "invalid_setup_token", null);
        }

        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength || password.Length > 256)
        {
            return (false, "weak_password", null);
        }

        var name = string.IsNullOrWhiteSpace(ownerName) ? _store.GetOwner().Name : ValidateName(ownerName);
        if (name is null)
        {
            return (false, "invalid_name", null);
        }

        string? key = null;
        var passwordHash = Secrets.HashPassword(password);
        string? keyHash = null;
        string? keyHint = null;
        if (generateAccessKey)
        {
            key = Secrets.NewAccessKey();
            keyHash = Secrets.Sha256Hex(key);
            keyHint = Secrets.AccessKeyHint(key);
        }

        _store.UpdateOwner(owner =>
        {
            owner.Name = name;
            owner.PasswordHash = passwordHash;
            owner.AccessKeyHash = keyHash;
            owner.AccessKeyHint = keyHint;
        });

        return (true, null, key);
    }

    public (bool Ok, string? Error) ChangePassword(string? currentPassword, string? newPassword)
    {
        if (PasswordManagedByEnv)
        {
            return (false, "managed_by_env");
        }

        if (!VerifyPassword(currentPassword))
        {
            return (false, "invalid_password");
        }

        if (string.IsNullOrEmpty(newPassword) || newPassword.Length < MinPasswordLength || newPassword.Length > 256)
        {
            return (false, "weak_password");
        }

        var hash = Secrets.HashPassword(newPassword);
        _store.UpdateOwner(owner => owner.PasswordHash = hash);
        return (true, null);
    }

    public (bool Ok, string? Error, string? PlainKey, string? Hint) RotateAccessKey()
    {
        if (AccessKeyManagedByEnv)
        {
            return (false, "managed_by_env", null, null);
        }

        var key = Secrets.NewAccessKey();
        var hash = Secrets.Sha256Hex(key);
        var hint = Secrets.AccessKeyHint(key);
        _store.UpdateOwner(owner =>
        {
            owner.AccessKeyHash = hash;
            owner.AccessKeyHint = hint;
        });

        return (true, null, key, hint);
    }

    public (bool Ok, string? Error) DisableAccessKey()
    {
        if (AccessKeyManagedByEnv)
        {
            return (false, "managed_by_env");
        }

        if (!PasswordEnabled)
        {
            return (false, "last_auth_method");
        }

        _store.UpdateOwner(owner =>
        {
            owner.AccessKeyHash = null;
            owner.AccessKeyHint = null;
        });

        return (true, null);
    }

    public OwnerProfile? RenameOwner(string? rawName)
    {
        var name = ValidateName(rawName);
        if (name is null)
        {
            return null;
        }

        return _store.UpdateOwner(owner => owner.Name = name);
    }

    public static string? ValidateName(string? raw)
    {
        var trimmed = raw?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > 64 || trimmed.Any(char.IsControl))
        {
            return null;
        }

        return trimmed;
    }
}
