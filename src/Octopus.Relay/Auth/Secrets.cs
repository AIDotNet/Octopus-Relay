using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Octopus.Relay.Auth;

/// <summary>Cryptographic helpers using pure .NET BCL primitives.</summary>
public static class Secrets
{
    private const string Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    private const int Pbkdf2Iterations = 310_000;
    private const int Pbkdf2SaltBytes = 16;
    private const int Pbkdf2HashBytes = 32;
    private const string Pbkdf2Prefix = "pbkdf2-sha256$";

    public static byte[] DeriveKey(byte[] secret, string purpose)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, salt: null, info: Encoding.UTF8.GetBytes("octopus/1 " + purpose));
    }

    public static byte[] Sha256(string text)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(text));
    }

    public static string Sha256Hex(string text)
    {
        return Convert.ToHexStringLower(Sha256(text));
    }

    public static string RandomToken(int bytes)
    {
        return Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(bytes));
    }

    public static string NewAccountId()
    {
        return RandomNumberGenerator.GetString(Base32Alphabet, 20);
    }

    public static string NewAccessKey()
    {
        return "ork_" + RandomToken(32);
    }

    public static string AccessKeyHint(string key)
    {
        if (key.Length <= 10)
        {
            return "••••";
        }

        return $"{key[..8]}…{key[^4..]}";
    }

    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    public static bool FixedTimeEqualsString(string left, string right)
    {
        return FixedTimeEquals(Sha256(left), Sha256(right));
    }

    /// <summary>Hashes an owner password with PBKDF2-SHA256 (<c>pbkdf2-sha256$&lt;iter&gt;$&lt;salt&gt;$&lt;hash&gt;</c>).</summary>
    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(Pbkdf2SaltBytes);
        var derived = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, Pbkdf2HashBytes);
        return $"{Pbkdf2Prefix}{Pbkdf2Iterations}${Base64Url.EncodeToString(salt)}${Base64Url.EncodeToString(derived)}";
    }

    public static bool VerifyPassword(string password, string? encoded)
    {
        if (string.IsNullOrEmpty(encoded) || !encoded.StartsWith(Pbkdf2Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = encoded.Split('$');
        if (parts.Length != 4
            || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var iterations)
            || iterations is < 10_000 or > 2_000_000)
        {
            return false;
        }

        try
        {
            var salt = Base64Url.DecodeFromChars(parts[2]);
            var expected = Base64Url.DecodeFromChars(parts[3]);
            if (salt.Length < 8 || expected.Length != Pbkdf2HashBytes)
            {
                return false;
            }

            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, Pbkdf2HashBytes);
            return FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
