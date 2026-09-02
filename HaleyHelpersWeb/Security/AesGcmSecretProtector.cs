using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Haley.Security;

public sealed record SecretProtectionKey(string KeyId, byte[] Key, bool IsActive = false)
{
    public static SecretProtectionKey FromFile(string keyId, string path, bool isActive = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length is not (16 or 24 or 32))
        {
            var text = Encoding.UTF8.GetString(bytes).Trim();
            try
            {
                bytes = Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
                throw new InvalidOperationException(
                    $"Secret-protection key '{keyId}' must contain 16, 24, or 32 raw bytes or their Base64 representation.");
            }
        }

        return new SecretProtectionKey(keyId, bytes, isActive);
    }
}

public interface ISecretEnvelopeProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose);
    byte[] Unprotect(ReadOnlySpan<byte> envelope, string purpose);
}

/// <summary>
/// Protects small secrets with a versioned AES-GCM envelope. The envelope carries only
/// the key identifier, nonce, authentication tag, and ciphertext; key material remains
/// outside the payload and may be rotated by retaining retiring keys for decryption.
/// </summary>
public sealed class AesGcmSecretProtector : ISecretEnvelopeProtector
{
    private const byte EnvelopeVersion = 1;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private static readonly byte[] AadPrefix = "haley.secret.v1"u8.ToArray();
    private readonly IReadOnlyDictionary<string, byte[]> _keys;
    private readonly string _activeKeyId;

    public AesGcmSecretProtector(IEnumerable<SecretProtectionKey> keys, string? activeKeyId = null)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var configured = keys.ToArray();
        if (configured.Length == 0) throw new ArgumentException("At least one secret-protection key is required.", nameof(keys));

        var duplicate = configured.GroupBy(item => item.KeyId, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null) throw new ArgumentException($"Secret-protection key id '{duplicate.Key}' is duplicated.", nameof(keys));
        if (configured.Any(item => string.IsNullOrWhiteSpace(item.KeyId) || item.KeyId.Length > byte.MaxValue))
            throw new ArgumentException("Every secret-protection key requires a key id no longer than 255 UTF-8 bytes.", nameof(keys));
        if (configured.Any(item => item.Key is null || item.Key.Length is not (16 or 24 or 32)))
            throw new ArgumentException("AES-GCM keys must contain 16, 24, or 32 bytes.", nameof(keys));

        var active = string.IsNullOrWhiteSpace(activeKeyId)
            ? configured.Where(item => item.IsActive).Select(item => item.KeyId).ToArray()
            : [activeKeyId.Trim()];
        if (active.Length != 1 || configured.All(item => !string.Equals(item.KeyId, active[0], StringComparison.Ordinal)))
            throw new ArgumentException("Exactly one configured secret-protection key must be active.", nameof(activeKeyId));

        _activeKeyId = active[0];
        _keys = configured.ToDictionary(
            item => item.KeyId,
            item => item.Key.ToArray(),
            StringComparer.Ordinal);
    }

    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose)
    {
        ValidatePurpose(purpose);
        var keyIdBytes = Encoding.UTF8.GetBytes(_activeKeyId);
        if (keyIdBytes.Length > byte.MaxValue) throw new InvalidOperationException("The active key id is too long for the envelope.");

        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];
        var aad = CreateAad(purpose, _activeKeyId);
        using (var aes = new AesGcm(_keys[_activeKeyId], TagLength))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }

        var envelope = new byte[1 + 1 + keyIdBytes.Length + NonceLength + TagLength + sizeof(int) + ciphertext.Length];
        var offset = 0;
        envelope[offset++] = EnvelopeVersion;
        envelope[offset++] = checked((byte)keyIdBytes.Length);
        keyIdBytes.CopyTo(envelope.AsSpan(offset));
        offset += keyIdBytes.Length;
        nonce.CopyTo(envelope.AsSpan(offset));
        offset += NonceLength;
        tag.CopyTo(envelope.AsSpan(offset));
        offset += TagLength;
        BinaryPrimitives.WriteInt32BigEndian(envelope.AsSpan(offset, sizeof(int)), ciphertext.Length);
        offset += sizeof(int);
        ciphertext.CopyTo(envelope.AsSpan(offset));
        CryptographicOperations.ZeroMemory(aad);
        return envelope;
    }

    public byte[] Unprotect(ReadOnlySpan<byte> envelope, string purpose)
    {
        ValidatePurpose(purpose);
        if (envelope.Length < 1 + 1 + NonceLength + TagLength + sizeof(int) || envelope[0] != EnvelopeVersion)
            throw new CryptographicException("The protected-secret envelope is invalid or unsupported.");

        var keyIdLength = envelope[1];
        var fixedLength = 1 + 1 + keyIdLength + NonceLength + TagLength + sizeof(int);
        if (keyIdLength == 0 || envelope.Length < fixedLength)
            throw new CryptographicException("The protected-secret envelope is truncated.");

        var offset = 2;
        var keyId = Encoding.UTF8.GetString(envelope.Slice(offset, keyIdLength));
        offset += keyIdLength;
        if (!_keys.TryGetValue(keyId, out var key))
            throw new CryptographicException($"Secret-protection key '{keyId}' is unavailable.");

        var nonce = envelope.Slice(offset, NonceLength);
        offset += NonceLength;
        var tag = envelope.Slice(offset, TagLength);
        offset += TagLength;
        var ciphertextLength = BinaryPrimitives.ReadInt32BigEndian(envelope.Slice(offset, sizeof(int)));
        offset += sizeof(int);
        if (ciphertextLength < 0 || envelope.Length - offset != ciphertextLength)
            throw new CryptographicException("The protected-secret envelope length is invalid.");

        var plaintext = new byte[ciphertextLength];
        var aad = CreateAad(purpose, keyId);
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(nonce, envelope[offset..], tag, plaintext, aad);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] CreateAad(string purpose, string keyId)
    {
        var purposeBytes = Encoding.UTF8.GetBytes(purpose);
        var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
        var result = new byte[AadPrefix.Length + 1 + purposeBytes.Length + 1 + keyIdBytes.Length];
        var offset = 0;
        AadPrefix.CopyTo(result, offset);
        offset += AadPrefix.Length + 1;
        purposeBytes.CopyTo(result, offset);
        offset += purposeBytes.Length + 1;
        keyIdBytes.CopyTo(result, offset);
        return result;
    }

    private static void ValidatePurpose(string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        if (purpose.Length > 200) throw new ArgumentOutOfRangeException(nameof(purpose));
    }
}
