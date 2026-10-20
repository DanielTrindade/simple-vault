using System.Security.Cryptography;
using System.Text;

namespace SVault.Core.Crypto;

/// <summary>
/// Standard primitives only (PBKDF2-HMAC-SHA512, HKDF-SHA256, AES-256-GCM) taken from the BCL.
/// The envelope protects a secret value with a key derived from the human-held passphrase.
/// </summary>
public static class VaultCrypto
{
    public const int SaltSize = 16;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;
    public const int KdfIterations = 210_000;

    public static byte[] RandomSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    public static byte[] RandomNonce() => RandomNumberGenerator.GetBytes(NonceSize);

    public static byte[] DeriveVaultKey(string passphrase, byte[] masterSalt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passphrase),
            masterSalt,
            KdfIterations,
            HashAlgorithmName.SHA512,
            KeySize);
    }

    public static byte[] DeriveEntryKey(byte[] vaultKey, string entryId, byte[] entrySalt)
    {
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            vaultKey,
            outputLength: KeySize,
            salt: entrySalt,
            info: Encoding.UTF8.GetBytes("svault:entry:" + entryId));
    }

    public static byte[] Seal(byte[] plaintext, byte[] key)
    {
        var nonce = RandomNonce();
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var envelope = new byte[1 + NonceSize + ciphertext.Length + TagSize];
        envelope[0] = 1;
        Buffer.BlockCopy(nonce, 0, envelope, 1, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, envelope, 1 + NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, envelope, 1 + NonceSize + ciphertext.Length, TagSize);
        return envelope;
    }

    public static bool TryOpen(byte[] envelope, byte[] key, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();
        if (envelope.Length < 1 + NonceSize + TagSize || envelope[0] != 1)
        {
            return false;
        }

        var nonce = envelope.AsSpan(1, NonceSize).ToArray();
        var ciphertextLength = envelope.Length - 1 - NonceSize - TagSize;
        var ciphertext = envelope.AsSpan(1 + NonceSize, ciphertextLength).ToArray();
        var tag = envelope.AsSpan(1 + NonceSize + ciphertextLength, TagSize).ToArray();

        var buffer = new byte[ciphertextLength];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, buffer);
        }
        catch (CryptographicException)
        {
            return false;
        }

        plaintext = buffer;
        return true;
    }

    public static string ToBase64(byte[] data) => Convert.ToBase64String(data);

    public static byte[] FromBase64(string data) => Convert.FromBase64String(data);

    public static bool FixedTimeEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);
}
