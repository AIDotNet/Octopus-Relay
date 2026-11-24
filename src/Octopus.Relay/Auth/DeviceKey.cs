using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Octopus.Relay.Auth;

/// <summary>
/// A device's ECDSA P-256 public key (65-byte uncompressed point <c>0x04 ‖ X ‖ Y</c>).
/// Matches the exact derivation and signature verification rules of Octopus clients.
/// </summary>
public sealed class DeviceKey
{
    public const int PublicKeyLength = 65;
    public const int SignatureLength = 64;
    public const int DeviceIdLength = 26;

    private const string Base32Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    private static readonly BigInteger P = BigInteger.Parse("0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger B = BigInteger.Parse("05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", System.Globalization.NumberStyles.HexNumber);

    private readonly byte[] _point;

    private DeviceKey(byte[] point)
    {
        _point = point;
        Id = DeriveId(point);
    }

    public string Id { get; }

    public ReadOnlySpan<byte> Bytes => _point;

    public static bool TryParse(ReadOnlySpan<byte> point, out DeviceKey key)
    {
        key = null!;
        if (point.Length != PublicKeyLength || point[0] != 0x04 || !IsOnCurve(point.Slice(1, 32), point.Slice(33, 32)))
        {
            return false;
        }

        try
        {
            using var check = Import(point);
        }
        catch (CryptographicException)
        {
            return false;
        }

        key = new DeviceKey(point.ToArray());
        return true;
    }

    public static bool TryParse(string? base64, out DeviceKey key)
    {
        key = null!;
        if (base64 is null || base64.Length > 128)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[96];
        return Convert.TryFromBase64String(base64, bytes, out var written) && TryParse(bytes[..written], out key);
    }

    /// <summary>First 16 bytes of SHA-256(publicKey) encoded in lower-case RFC 4648 base32 (26 chars).</summary>
    public static string DeriveId(ReadOnlySpan<byte> publicKey)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(publicKey, hash);
        var text = new StringBuilder(DeviceIdLength);
        var buffer = 0;
        var bits = 0;
        foreach (var value in hash[..16])
        {
            buffer = ((buffer << 8) | value) & 0xFFFF;
            bits += 8;
            while (bits >= 5)
            {
                text.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            text.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return text.ToString();
    }

    public static bool IsDeviceId(string? text)
    {
        if (text is null || text.Length != DeviceIdLength)
        {
            return false;
        }

        foreach (var c in text)
        {
            if (!Base32Alphabet.Contains(c))
            {
                return false;
            }
        }

        return true;
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != SignatureLength)
        {
            return false;
        }

        try
        {
            using var key = Import(_point);
            return key.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Hash signed by a host on <c>/v1/host</c>: <c>SHA-256("octopus-relay/1 host\n" ‖ nonce)</c>.</summary>
    public static byte[] HostRegistrationHash(ReadOnlySpan<byte> nonce)
    {
        return LabelledHash("octopus-relay/1 host\n"u8, nonce);
    }

    /// <summary>Hash signed by a device redeeming a device code: <c>SHA-256("octopus-relay/1 login\n" ‖ deviceCode)</c>.</summary>
    public static byte[] LoginHash(string deviceCode)
    {
        return LabelledHash("octopus-relay/1 login\n"u8, Encoding.ASCII.GetBytes(deviceCode));
    }

    /// <summary>Hash signed by a device signing in with an access key: <c>SHA-256("octopus-relay/1 key-login\n" ‖ challenge)</c>.</summary>
    public static byte[] KeyLoginHash(ReadOnlySpan<byte> challenge)
    {
        return LabelledHash("octopus-relay/1 key-login\n"u8, challenge);
    }

    private static byte[] LabelledHash(ReadOnlySpan<byte> label, ReadOnlySpan<byte> data)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(label);
        hash.AppendData(data);
        return hash.GetHashAndReset();
    }

    private static ECDsa Import(ReadOnlySpan<byte> point)
    {
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point.Slice(1, 32).ToArray(), Y = point.Slice(33, 32).ToArray() },
        });
    }

    private static bool IsOnCurve(ReadOnlySpan<byte> xBytes, ReadOnlySpan<byte> yBytes)
    {
        var x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);
        var y = new BigInteger(yBytes, isUnsigned: true, isBigEndian: true);
        if (x >= P || y >= P)
        {
            return false;
        }

        var left = y * y % P;
        var right = ((x * x * x) - (3 * x) + B) % P;
        if (right < 0)
        {
            right += P;
        }

        return left == right;
    }
}
