using Haley.Abstractions;
using Haley.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Haley.Models {
    public class PlainQueryAuthHandler : PlainAuthHandlerBase<PlainAuthOptions> {
        public PlainQueryAuthHandler(IOptionsMonitor<PlainAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock) {
        }
        protected override PlainAuthMode AuthMode { get; set; } = PlainAuthMode.QueryToken;
    }
}
