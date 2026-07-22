using Haley.Abstractions;
using Haley.Enums;
using Haley.Models;
using Haley.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Haley.Models {

    public class PlainHeaderJWTHandler : PlainAuthHandlerBase<JwtAuthOptions> {

        public PlainHeaderJWTHandler(IOptionsMonitor<JwtAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock) {
        }

        protected override PlainAuthMode AuthMode { get; set; } = PlainAuthMode.HeaderJWT;

        protected override Func<HttpContext, string, ILogger, Task<PlainAuthResult>>? PrepareClaims => async (c, t, l) => {
            if (string.IsNullOrEmpty(t)) return new PlainAuthResult { Status = false, Message = "Token is null or empty." };
            var jwtOptions = OptionsMonitor.Get(Scheme.Name);
            var claimsPrincipal = JWTUtil.ValidateToken(t, jwtOptions.ValidationParams, out var validatedToken, Scheme.Name);
            return new PlainAuthResult() { Status =  claimsPrincipal != null,Principal = claimsPrincipal, Message = "Token validated successfully." };
        };
    }
}