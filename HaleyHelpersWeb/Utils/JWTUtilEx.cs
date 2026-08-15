using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Identity.Client;
using Haley.Models;
using Haley.Utils;
using Microsoft.AspNetCore.DataProtection;
using System.Text;

namespace Haley.Utils {

    public static class JWTUtilEx {

        public static void ConfigureDefaultJWTAuth(JwtAuthOptions options) {
            var jwtparams = AppMaker.JWTParams;
            //options.Params = Globals.JWTParams;
            options.ValidationParams = JWTUtil.GenerateTokenValidationParams(jwtparams);
        }

        public static async Task<JwtSecurityToken> GetJwtToken(this HttpContext input,string key= "access_token") {
            try {
                var accessToken = await input.GetTokenAsync(key); //this will work only if we have set the "savetoken=true" in the jWT Bearer settings.
                return new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
            } catch (Exception ex) {
                return null;
            }
        }

        public static async Task<string> GetJwtClaim(this HttpContext context,string claimName, string key = "access_token") {
            var jwt = await context.GetJwtToken(key);
            if (jwt == null) throw new ArgumentNullException("JWT token is null. Hint: Add token in authorization or Ensure the JWTBearerOptions has SaveToken set to true.");
            return jwt?.Claims?.FirstOrDefault(p => p.Type == claimName)?.Value ?? null;
        }


        public static async Task<string> GetDBA(this HttpContext context) {
            return await context.GetJwtClaim(BaseClaimTypes.DBA_KEY);
        }

        public static AuthenticationBuilder AddJwtBearerScheme(this AuthenticationBuilder builder, string scheme, Action<JwtAuthOptions> configureOptions) {
            builder.AddScheme<JwtAuthOptions, PlainHeaderJWTHandler>(scheme, options => { }); //Dont set the options, here, otherwise, it will override, the options monitor
            // Register named options for this scheme
            builder.Services.Configure<JwtAuthOptions>(scheme, configureOptions);
            return builder;
        }

        /// <summary>
        /// Registers a bearer scheme whose validation parameters can be resolved
        /// asynchronously for each request.
        /// </summary>
        public static AuthenticationBuilder AddJwtBearerScheme(
            this AuthenticationBuilder builder,
            string scheme,
            JwtValidationParametersResolver validationParametersResolver,
            Action<JwtAuthOptions>? configureOptions = null) {
            if (validationParametersResolver is null) throw new ArgumentNullException(nameof(validationParametersResolver));
            return builder.AddJwtBearerScheme(scheme, options => {
                configureOptions?.Invoke(options);
                options.ValidationParametersResolver = validationParametersResolver;
            });
        }
    }
}
