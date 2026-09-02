using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Haley.Security;

public sealed class SamlAssertionValidationOptions
{
    public bool ValidateSignature { get; set; } = true;
    public bool ValidateIssuer { get; set; } = true;
    public bool ValidateAudience { get; set; } = true;
    public bool ValidateLifetime { get; set; } = true;
    public bool ValidateDestination { get; set; } = true;
    public bool ValidateRecipient { get; set; } = true;
    public bool ValidateInResponseTo { get; set; } = true;
    public bool ValidateReplay { get; set; } = true;
    public bool AllowUnsafeValidation { get; set; }
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);
    public int MaximumXmlCharacters { get; set; } = 1_048_576;

    public void ValidateConfiguration()
    {
        if ((!ValidateSignature || !ValidateReplay) && !AllowUnsafeValidation)
        {
            throw new InvalidOperationException(
                "Disabling SAML signature or replay validation requires AllowUnsafeValidation=true.");
        }

        if (ClockSkew < TimeSpan.Zero || ClockSkew > TimeSpan.FromMinutes(10))
            throw new InvalidOperationException("SAML clock skew must be between zero and ten minutes.");
        if (MaximumXmlCharacters is < 1_024 or > 10_485_760)
            throw new InvalidOperationException("SAML XML size must be between 1 KiB and 10 MiB.");
    }
}

public sealed record SamlAssertionValidationContext(
    IReadOnlyCollection<X509Certificate2> SigningCertificates,
    string? ExpectedIssuer,
    string? ExpectedAudience,
    string? ExpectedDestination,
    string? ExpectedInResponseTo,
    DateTimeOffset EvaluatedAt);

public sealed record ValidatedSamlAssertion(
    string ResponseId,
    string AssertionId,
    string Issuer,
    string Subject,
    IReadOnlyCollection<Claim> Claims,
    DateTimeOffset? ExpiresAt,
    string? InResponseTo);

public interface ISamlReplayValidator
{
    ValueTask<bool> TryConsumeAsync(
        string responseId,
        string assertionId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Validates a SAML 2.0 HTTP-POST response without trusting unsigned copies of
/// assertions. The caller owns metadata refresh and durable replay storage.
/// </summary>
public sealed class SamlAssertionValidator
{
    private const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";

    public async ValueTask<ValidatedSamlAssertion> ValidateAsync(
        string base64Response,
        SamlAssertionValidationContext context,
        SamlAssertionValidationOptions options,
        ISamlReplayValidator? replayValidator = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Response);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);
        options.ValidateConfiguration();

        byte[] payload;
        try { payload = Convert.FromBase64String(base64Response); }
        catch (FormatException exception) { throw new InvalidDataException("The SAML response is not valid Base64.", exception); }

        var document = LoadDocument(payload, options.MaximumXmlCharacters);
        var response = document.DocumentElement;
        if (response is null || response.LocalName != "Response" || response.NamespaceURI != ProtocolNamespace)
            throw new InvalidDataException("The SAML document must contain one protocol Response root.");

        var assertions = response.ChildNodes.OfType<XmlElement>()
            .Where(element => element.LocalName == "Assertion" && element.NamespaceURI == AssertionNamespace)
            .ToArray();
        if (assertions.Length != 1)
            throw new InvalidDataException("The SAML response must contain exactly one direct Assertion.");
        var assertion = assertions[0];

        var responseId = RequireUniqueId(document, response);
        var assertionId = RequireUniqueId(document, assertion);
        if (options.ValidateSignature)
            ValidateSignature(document, response, assertion, context.SigningCertificates);

        var issuer = assertion.ChildNodes.OfType<XmlElement>()
            .SingleOrDefault(element => element.LocalName == "Issuer" && element.NamespaceURI == AssertionNamespace)
            ?.InnerText.Trim() ?? throw new InvalidDataException("The SAML assertion issuer is missing.");
        if (options.ValidateIssuer && !FixedEquals(issuer, context.ExpectedIssuer))
            throw new InvalidDataException("The SAML assertion issuer is invalid.");

        var destination = response.GetAttribute("Destination");
        if (options.ValidateDestination && !FixedEquals(destination, context.ExpectedDestination))
            throw new InvalidDataException("The SAML response destination is invalid.");
        var inResponseTo = NullIfEmpty(response.GetAttribute("InResponseTo"));
        if (options.ValidateInResponseTo && !FixedEquals(inResponseTo, context.ExpectedInResponseTo))
            throw new InvalidDataException("The SAML response does not match the originating authentication request.");

        var conditions = assertion.ChildNodes.OfType<XmlElement>()
            .SingleOrDefault(element => element.LocalName == "Conditions" && element.NamespaceURI == AssertionNamespace);
        var expiresAt = conditions is null ? null : ParseInstant(conditions.GetAttribute("NotOnOrAfter"));
        if (options.ValidateLifetime)
        {
            if (conditions is null) throw new InvalidDataException("The SAML assertion conditions are missing.");
            ValidateLifetime(conditions, context.EvaluatedAt, options.ClockSkew);
        }

        if (options.ValidateAudience)
        {
            var audiences = assertion.GetElementsByTagName("Audience", AssertionNamespace)
                .OfType<XmlElement>().Select(element => element.InnerText.Trim()).ToArray();
            if (string.IsNullOrWhiteSpace(context.ExpectedAudience) ||
                !audiences.Any(value => FixedEquals(value, context.ExpectedAudience)))
                throw new InvalidDataException("The SAML assertion audience is invalid.");
        }

        var confirmations = assertion.GetElementsByTagName("SubjectConfirmationData", AssertionNamespace)
            .OfType<XmlElement>().ToArray();
        if (options.ValidateRecipient)
        {
            if (confirmations.Length == 0 || !confirmations.Any(item =>
                    FixedEquals(item.GetAttribute("Recipient"), context.ExpectedDestination)))
                throw new InvalidDataException("The SAML subject-confirmation recipient is invalid.");
        }
        if (options.ValidateInResponseTo && confirmations.Any(item =>
                !string.IsNullOrWhiteSpace(item.GetAttribute("InResponseTo")) &&
                !FixedEquals(item.GetAttribute("InResponseTo"), context.ExpectedInResponseTo)))
            throw new InvalidDataException("The SAML subject confirmation does not match the authentication request.");

        var subject = assertion.GetElementsByTagName("NameID", AssertionNamespace)
            .OfType<XmlElement>().SingleOrDefault()?.InnerText.Trim();
        if (string.IsNullOrWhiteSpace(subject)) throw new InvalidDataException("The SAML subject is missing.");

        if (options.ValidateReplay)
        {
            if (replayValidator is null) throw new InvalidOperationException("SAML replay validation requires an ISamlReplayValidator.");
            var replayExpiry = expiresAt ?? context.EvaluatedAt.AddMinutes(5);
            if (!await replayValidator.TryConsumeAsync(responseId, assertionId, replayExpiry, cancellationToken).ConfigureAwait(false))
                throw new InvalidDataException("The SAML response has already been consumed.");
        }

        return new(responseId, assertionId, issuer, subject, ExtractClaims(assertion, issuer), expiresAt, inResponseTo);
    }

    private static XmlDocument LoadDocument(byte[] payload, int maximumCharacters)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = maximumCharacters,
            MaxCharactersFromEntities = 0
        };
        using var stream = new MemoryStream(payload, writable: false);
        using var reader = XmlReader.Create(stream, settings);
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.Load(reader);
        return document;
    }

    private static string RequireUniqueId(XmlDocument document, XmlElement element)
    {
        var id = element.GetAttribute("ID");
        if (string.IsNullOrWhiteSpace(id)) throw new InvalidDataException($"The SAML {element.LocalName} ID is missing.");
        var matches = document.SelectNodes("//*[@ID]")!.OfType<XmlElement>()
            .Count(candidate => string.Equals(candidate.GetAttribute("ID"), id, StringComparison.Ordinal));
        if (matches != 1) throw new InvalidDataException("The SAML document contains a duplicate ID.");
        return id;
    }

    private static void ValidateSignature(
        XmlDocument document,
        XmlElement response,
        XmlElement assertion,
        IReadOnlyCollection<X509Certificate2> certificates)
    {
        if (certificates.Count == 0) throw new InvalidOperationException("No SAML signing certificate is configured.");
        var signedElement = FindDirectSignature(response) is not null ? response : assertion;
        var signatureElement = FindDirectSignature(signedElement)
            ?? throw new InvalidDataException("The SAML response or assertion is not signed.");
        if (document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl).Count != 1)
            throw new InvalidDataException("The SAML response must contain exactly one signature.");

        var signedXml = new SignedXml(signedElement);
        signedXml.LoadXml(signatureElement);
        if (signedXml.SignedInfo is null || signedXml.SignedInfo.References.Count != 1)
            throw new InvalidDataException("The SAML signature must contain exactly one reference.");
        var reference = (Reference)signedXml.SignedInfo.References[0]!;
        if (!string.Equals(reference.Uri, $"#{signedElement.GetAttribute("ID")}", StringComparison.Ordinal) ||
            !string.Equals(reference.DigestMethod, SignedXml.XmlDsigSHA256Url, StringComparison.Ordinal))
            throw new InvalidDataException("The SAML signature does not bind the selected element with SHA-256.");
        if (!string.Equals(signedXml.SignedInfo.SignatureMethod, SignedXml.XmlDsigRSASHA256Url, StringComparison.Ordinal))
            throw new InvalidDataException("Only RSA-SHA256 SAML signatures are accepted.");
        if (!certificates.Any(certificate => signedXml.CheckSignature(certificate, true)))
            throw new InvalidDataException("The SAML signature is invalid.");
    }

    private static XmlElement? FindDirectSignature(XmlElement parent) => parent.ChildNodes.OfType<XmlElement>()
        .SingleOrDefault(element => element.LocalName == "Signature" && element.NamespaceURI == SignedXml.XmlDsigNamespaceUrl);

    private static void ValidateLifetime(XmlElement conditions, DateTimeOffset now, TimeSpan skew)
    {
        var notBefore = ParseInstant(conditions.GetAttribute("NotBefore"));
        var notOnOrAfter = ParseInstant(conditions.GetAttribute("NotOnOrAfter"));
        if (notBefore is not null && now + skew < notBefore) throw new InvalidDataException("The SAML assertion is not yet valid.");
        if (notOnOrAfter is null || now - skew >= notOnOrAfter) throw new InvalidDataException("The SAML assertion has expired.");
    }

    private static DateTimeOffset? ParseInstant(string value) => string.IsNullOrWhiteSpace(value)
        ? null
        : DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static IReadOnlyCollection<Claim> ExtractClaims(XmlElement assertion, string issuer)
    {
        var claims = new List<Claim>();
        foreach (var attribute in assertion.GetElementsByTagName("Attribute", AssertionNamespace).OfType<XmlElement>())
        {
            var type = attribute.GetAttribute("Name").Trim();
            if (type.Length == 0) continue;
            foreach (var value in attribute.GetElementsByTagName("AttributeValue", AssertionNamespace).OfType<XmlElement>())
            {
                var content = value.InnerText.Trim();
                if (content.Length > 0) claims.Add(new Claim(type, content, ClaimValueTypes.String, issuer));
            }
        }
        return claims;
    }

    private static bool FixedEquals(string? actual, string? expected) =>
        !string.IsNullOrWhiteSpace(expected) && string.Equals(actual?.Trim(), expected.Trim(), StringComparison.Ordinal);
    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
