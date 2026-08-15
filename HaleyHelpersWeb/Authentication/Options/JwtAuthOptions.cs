using Haley.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
namespace Haley.Models {
    /// <summary>
    /// Resolves token-validation parameters at request time. Use this when a signing
    /// key must be loaded asynchronously from a key store, discovery endpoint, HSM,
    /// or another application-owned provider.
    /// </summary>
    /// <param name="context">The current authentication request.</param>
    /// <param name="token">The raw bearer token being validated.</param>
    /// <param name="cancellationToken">The request cancellation token.</param>
    public delegate ValueTask<TokenValidationParameters?> JwtValidationParametersResolver(
        HttpContext context,
        string token,
        CancellationToken cancellationToken);

    public class JwtAuthOptions : PlainAuthOptions {
        //public JWTParameters Params { get; set; }
        public TokenValidationParameters? ValidationParams { get; set; }

        /// <summary>
        /// Optional asynchronous request-time resolver. When configured, this takes
        /// precedence over <see cref="ValidationParams"/>.
        /// </summary>
        public JwtValidationParametersResolver? ValidationParametersResolver { get; set; }

        public JwtAuthOptions() { base.Key = "Bearer"; }
    }
}
