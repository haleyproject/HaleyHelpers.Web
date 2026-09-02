using System.Security.Cryptography;
using Haley.Security;
using Xunit;

namespace HaleyHelpersWeb.Tests;

public sealed class AesGcmSecretProtectorTests
{
    [Fact]
    public void RoundTripAndRetiringKeyDecryptionWork()
    {
        var retiring = RandomNumberGenerator.GetBytes(32);
        var active = RandomNumberGenerator.GetBytes(32);
        var oldProtector = new AesGcmSecretProtector([
            new SecretProtectionKey("old", retiring, true)
        ]);
        var oldEnvelope = oldProtector.Protect("totp-secret"u8, "kida.mfa.totp");

        var rotated = new AesGcmSecretProtector([
            new SecretProtectionKey("old", retiring),
            new SecretProtectionKey("new", active, true)
        ]);

        Assert.Equal("totp-secret"u8.ToArray(), rotated.Unprotect(oldEnvelope, "kida.mfa.totp"));
        Assert.Equal("totp-secret"u8.ToArray(), rotated.Unprotect(
            rotated.Protect("totp-secret"u8, "kida.mfa.totp"),
            "kida.mfa.totp"));
    }

    [Fact]
    public void TamperingOrWrongPurposeIsRejected()
    {
        var protector = new AesGcmSecretProtector([
            new SecretProtectionKey("active", RandomNumberGenerator.GetBytes(32), true)
        ]);
        var envelope = protector.Protect("sensitive"u8, "purpose-a");
        envelope[^1] ^= 0x40;

        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(envelope, "purpose-a"));
        var valid = protector.Protect("sensitive"u8, "purpose-a");
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(valid, "purpose-b"));
    }
}
