using System.Security.Cryptography;
using System.Text;

namespace SVault.Core.Crypto;

/// <summary>RFC 6238 TOTP (SHA-1, 30 second step, 6 digits).</summary>
public static class Totp
{
    private const int DefaultStepSeconds = 30;
    private const int DefaultDigits = 6;

    private static readonly DateTime UnixEpoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static string GenerateCode(string base32Secret, DateTime utcNow, int stepSeconds = DefaultStepSeconds, int digits = DefaultDigits)
    {
        var key = Base32.Decode(base32Secret);
        var counter = (long)(utcNow - UnixEpoch).TotalSeconds / stepSeconds;
        return ComputeHotp(key, counter, digits);
    }

    public static bool VerifyCode(string base32Secret, string code, DateTime utcNow, int window = 1, int stepSeconds = DefaultStepSeconds, int digits = DefaultDigits)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var normalized = code.Trim().Replace(" ", string.Empty).Replace("-", string.Empty);
        if (normalized.Length != digits || !normalized.All(char.IsAsciiDigit))
        {
            return false;
        }

        var key = Base32.Decode(base32Secret);
        var counter = (long)(utcNow - UnixEpoch).TotalSeconds / stepSeconds;

        for (var drift = -window; drift <= window; drift++)
        {
            var candidate = ComputeHotp(key, counter + drift, digits);
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(candidate),
                    Encoding.ASCII.GetBytes(normalized)))
            {
                return true;
            }
        }

        return false;
    }

    public static string GenerateSecret(int lengthBytes = 20)
    {
        return Base32.Encode(RandomNumberGenerator.GetBytes(lengthBytes));
    }

    public static string BuildOtpAuthUri(string secret, string account, string issuer = "SVault")
    {
        var label = Uri.EscapeDataString($"{issuer}:{account}");
        return $"otpauth://totp/{label}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";
    }

    private static string ComputeHotp(byte[] key, long counter, int digits)
    {
        var buffer = new byte[8];
        for (var i = 7; i >= 0; i--)
        {
            buffer[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(buffer);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                     | ((hash[offset + 1] & 0xFF) << 16)
                     | ((hash[offset + 2] & 0xFF) << 8)
                     | (hash[offset + 3] & 0xFF);

        var modulo = (int)Math.Pow(10, digits);
        return (binary % modulo).ToString("D" + digits);
    }
}

public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(byte[] data)
    {
        var builder = new StringBuilder((data.Length * 8 / 5) + 1);
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                builder.Append(Alphabet[(buffer >> (bitsLeft - 5)) & 0x1F]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            builder.Append(Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }

        return builder.ToString();
    }

    public static byte[] Decode(string encoded)
    {
        var cleaned = encoded.Replace(" ", string.Empty).Replace("-", string.Empty).TrimEnd('=');
        var bytes = new List<byte>(cleaned.Length * 5 / 8);
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var c in cleaned.ToUpperInvariant())
        {
            var index = Alphabet.IndexOf(c);
            if (index < 0)
            {
                throw new FormatException("Invalid base32 character.");
            }

            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }

        return bytes.ToArray();
    }
}
