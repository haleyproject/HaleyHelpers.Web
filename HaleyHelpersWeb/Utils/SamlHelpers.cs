using Haley.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Haley.Utils {
    public class SamlHelpers {
        // Common SAML/Entra URIs
        internal const string NsSaml = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string pathNameId = "//saml:Assertion/saml:Subject/saml:NameID";
        internal const string pathAttribute = "//saml:AttributeStatement/saml:Attribute";

        // Azure AD (Microsoft Entra) typical claim URIs
        //private const string CLAIM_EMAIL = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
        //private const string CLAIM_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
        //private const string CLAIM_UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
        private const string CLAIM_OID = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        private const string CLAIM_TID = "http://schemas.microsoft.com/identity/claims/tenantid";
        private const string CLAIM_GRP = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";

        /// <summary>
        /// Extracts a baseline set of claims from a validated SAML Response/Assertion.
        /// </summary>
        public static List<Claim> ExtractClaims(XmlDocument doc, string issuer) {
            var claims = new List<Claim>();
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("saml", NsSaml);

            // NameID
            var nameId = doc.SelectSingleNode(pathNameId, ns)?.InnerText?.Trim();
            if (!string.IsNullOrWhiteSpace(nameId))
                claims.Add(new Claim(ClaimTypes.NameIdentifier, nameId, ClaimValueTypes.String, issuer));

            // Attribute statements
            foreach (XmlElement attr in doc.SelectNodes(pathAttribute, ns)!) {
                var name = attr.GetAttribute("Name")?.Trim();
                if (string.IsNullOrWhiteSpace(name)) continue;

                foreach (XmlElement valNode in attr.GetElementsByTagName("AttributeValue", NsSaml)) {
                    var value = valNode.InnerText?.Trim();
                    if (string.IsNullOrWhiteSpace(value)) continue;

                    var mappedType = MapKnownType(name);
                    claims.Add(new Claim(mappedType, value, ClaimValueTypes.String, issuer));
                }
            }

            // Optional: ensure a friendly display name fallback
            if (!claims.Any(c => c.Type == ClaimTypes.Name)) {
                var upn = claims.FirstOrDefault(c => c.Type == "upn")?.Value
                          ?? claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                          ?? nameId;
                if (!string.IsNullOrWhiteSpace(upn))
                    claims.Add(new Claim(ClaimTypes.Name, upn, ClaimValueTypes.String, issuer));
            }

            return claims;
        }
        public static string BuildAuthnRedirectUrl(string ssoUrl, SamlAuthOptions opts, string relayState = "/") {
            // Create SAML 2.0 AuthnRequest XML
            var id = "_" + Guid.NewGuid().ToString("N");
            var issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            var xml = $@"
                <samlp:AuthnRequest
                    xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
                    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
                    ID=""{id}""
                    Version=""2.0""
                    IssueInstant=""{issueInstant}""
                    ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
                    AssertionConsumerServiceURL=""{opts.AcsUrl}"">
                    <saml:Issuer>{opts.SpEntityId}</saml:Issuer>
                    <samlp:NameIDPolicy Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"" AllowCreate=""true"" />
                </samlp:AuthnRequest>";

            // Compress and Base64-encode the AuthnRequest
            var bytes = Encoding.UTF8.GetBytes(xml);
            using var output = new MemoryStream();
            using (var deflate = new DeflateStream(output, CompressionMode.Compress, true)) {
                deflate.Write(bytes, 0, bytes.Length);
                deflate.Close();
            }
                
            var deflated = output.ToArray();
            var samlRequest = Convert.ToBase64String(deflated);
            // Build the redirect URL with query params
            var query = $"SAMLRequest={Uri.EscapeDataString(samlRequest)}&RelayState={Uri.EscapeDataString(relayState)}";
            return $"{ssoUrl}?{query}";
        }
        public static IResult UserLogin(string relay_state) {
            var cfg = ResourceUtils.GenerateConfigurationRoot();
            var samlSection = cfg.GetSection("Saml:Azure");
            var opts = new SamlAuthOptions {
                SpEntityId = samlSection["SpEntityId"]!,
                AcsUrl = samlSection["AcsUrl"]!
            };

            // Microsoft Entra SSO URL for Redirect binding
            var tenantId = samlSection["TenantId"]; // e.g. 245b2389c5
            var ssoUrl = $"https://login.microsoftonline.com/{tenantId}/saml2";

            // Build redirect
            var redirectUrl = SamlHelpers.BuildAuthnRedirectUrl(ssoUrl, opts, relayState: relay_state);
            return Results.Redirect(redirectUrl);
        }
        private static string MapKnownType(string samlName) {
            return samlName switch {
                ClaimTypes.Email or "email" => ClaimTypes.Email,
                ClaimTypes.Name or "name" => ClaimTypes.Name,
                ClaimTypes.Upn => "upn",
                CLAIM_OID => "oid",
                CLAIM_TID => "tid",
                CLAIM_GRP => ClaimTypes.GroupSid, // or a custom "groups" type if you prefer
                _ => samlName // keep original URI for unknowns
            };
        }
       

        public static PlainAuthResult ValidateAzurePayload(HttpRequest request, string base64Xml, ILogger log, string scheme_name, SamlAuthOptions options) { 
            try {
                if (string.IsNullOrWhiteSpace(base64Xml)) return new PlainAuthResult() { Status = false, Message = "SAML response is missing" };

                var audience = string.IsNullOrWhiteSpace(options.Audience) ? options.SpEntityId : options.Audience;

                // 1) Decode XML
                var xml = base64Xml.SafeBase64DecodeAsString();

                // 2) Load XML
                var doc = new XmlDocument { PreserveWhitespace = true };
                doc.LoadXml(xml);

                // 3) Get signing cert (from options or metadata loader you register via DI)
                //Idea behind the samlmetadacache is to avoid fetching metadata on every request. Its like, we download the certificate from the metadata once and cache it for later use. Sometimes, the server will rotate the certificate, so we need to have a way to refresh it periodically.

                var cert = options.SigningCert; //?? await SamlMetadataCache.GetSigningCertAsync(o.IdpMetadataUrl, ctx.RequestServices, log); 

                // 4) Validate signature on Response or Assertion
                if (!ValidateSignature(doc, cert)) return new PlainAuthResult() { Status = false, Message = "Invalid SAML signature" };

                // 5) Validate Conditions (NotBefore/NotOnOrAfter) and Audience
                if (!ValidateConditionsAndAudience(doc, audience, options.AllowedClockSkew)) return new PlainAuthResult() { Status = false, Message = "SAML conditions/audience check failed" };

                // 6) Extract claims (NameID + attributes you care about)
                var claims = ExtractClaims(doc, options.SpEntityId);
                string relayState = "/";
                if(request.HasFormContentType && request.Form.TryGetValue("RelayState", out var sr)) {
                    relayState = sr.ToString();
                } else if (request.Query.TryGetValue("RelayState", out var qr)) {
                    relayState = qr.ToString();
                }
                claims.Add(new Claim(BaseClaimTypes.RELAY_STATE, relayState));

                return new PlainAuthResult() { Status = true, Message = "SAML validation successful", Result = claims };
            } catch (Exception ex) {
                log?.LogError(ex, "SAML validation failed");
                return new PlainAuthResult() { Status = false, Message = "SAML validation error: " + ex.Message };
            }
        }

        static bool ValidateSignature(XmlDocument doc, X509Certificate2 cert) {
            // Try Response-level signature first
            var sigEl = (XmlElement?)doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl).Cast<XmlElement?>().FirstOrDefault();
            if (sigEl == null) return false;

            var parent = sigEl.ParentNode as XmlElement;   // Response or Assertion
            var sx = new SignedXml(parent);
            sx.LoadXml(sigEl);
            return sx.CheckSignature(cert, true);
        }

        static bool ValidateConditionsAndAudience(XmlDocument doc, string audience, TimeSpan skew) {
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("saml", SamlHelpers.NsSaml);

            var conditions = doc.SelectSingleNode("//saml:Assertion/saml:Conditions", ns) as XmlElement;
            if (conditions != null) {
                DateTime? nb = TryParse(conditions.GetAttribute("NotBefore"));
                DateTime? na = TryParse(conditions.GetAttribute("NotOnOrAfter"));
                var now = DateTime.UtcNow;
                if (nb.HasValue && now + skew < nb.Value) return false;
                if (na.HasValue && now - skew >= na.Value) return false;
            }

            var aud = doc.SelectSingleNode("//saml:Audience", ns)?.InnerText?.Trim();
            return string.IsNullOrWhiteSpace(aud) || string.Equals(aud, audience, StringComparison.OrdinalIgnoreCase);

            static DateTime? TryParse(string v) => string.IsNullOrWhiteSpace(v) ? null : DateTime.Parse(v, null, System.Globalization.DateTimeStyles.AdjustToUniversal);
        }
    }
}
