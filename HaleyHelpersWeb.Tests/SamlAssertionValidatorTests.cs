using System.Security.Cryptography.X509Certificates;
using System.Text;
using Haley.Security;
using Xunit;

namespace HaleyHelpersWeb.Tests;

public sealed class SamlAssertionValidatorTests
{
    [Fact]
    public void SignatureOrReplayCannotBeDisabledAccidentally()
    {
        var options = new SamlAssertionValidationOptions { ValidateSignature = false };
        Assert.Throws<InvalidOperationException>(options.ValidateConfiguration);
    }

    [Fact]
    public async Task NonSuccessfulResponseIsRejectedBeforeClaimsAreAccepted()
    {
        const string xml = """
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder" /></samlp:Status>
              <saml:Assertion ID="a1"><saml:Issuer>issuer</saml:Issuer><saml:Subject><saml:NameID>subject</saml:NameID></saml:Subject></saml:Assertion>
            </samlp:Response>
            """;
        var options = new SamlAssertionValidationOptions
        {
            ValidateSignature = false,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateDestination = false,
            ValidateRecipient = false,
            ValidateInResponseTo = false,
            ValidateReplay = false,
            AllowUnsafeValidation = true
        };
        var context = new SamlAssertionValidationContext(
            Array.Empty<X509Certificate2>(), null, null, null, null, DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<InvalidDataException>(() => new SamlAssertionValidator()
            .ValidateAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)), context, options).AsTask());
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task SuccessfulAssertionRequiresAuthenticationStatementAndBearerConfirmation(
        bool includeAuthnStatement,
        bool includeBearerConfirmation)
    {
        var confirmation = includeBearerConfirmation
            ? "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData /></saml:SubjectConfirmation>"
            : string.Empty;
        var authn = includeAuthnStatement
            ? "<saml:AuthnStatement AuthnInstant=\"2026-09-02T08:00:00Z\" />"
            : string.Empty;
        var xml = $$"""
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>
              <saml:Assertion ID="a1">
                <saml:Issuer>issuer</saml:Issuer>
                <saml:Subject><saml:NameID>subject</saml:NameID>{{confirmation}}</saml:Subject>
                {{authn}}
              </saml:Assertion>
            </samlp:Response>
            """;
        var options = UnsafeStructuralOptions();
        var context = new SamlAssertionValidationContext(
            Array.Empty<X509Certificate2>(), null, null, null, null, DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<InvalidDataException>(() => new SamlAssertionValidator()
            .ValidateAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)), context, options).AsTask());
    }

    private static SamlAssertionValidationOptions UnsafeStructuralOptions() => new()
    {
        ValidateSignature = false,
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = false,
        ValidateDestination = false,
        ValidateRecipient = false,
        ValidateInResponseTo = false,
        ValidateReplay = false,
        AllowUnsafeValidation = true
    };
}
