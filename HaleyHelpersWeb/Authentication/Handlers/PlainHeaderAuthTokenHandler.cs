using Haley.Abstractions;
using Haley.Enums;
using Haley.Models;
using Haley.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Haley.Models {

    public class PlainHeaderAuthTokenHandler : PlainAuthHandlerBase<HeaderAuthOptions> {

        public PlainHeaderAuthTokenHandler(IOptionsMonitor<HeaderAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock) {
        }

        protected override PlainAuthMode AuthMode { get; set; } = PlainAuthMode.HeaderAuthToken;
    }
}