using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Haley.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace HaleyHelpersWeb.Tests;

public sealed class PlainHeaderJwtHandlerTests
{
    [Fact]
    public async Task UsesAsynchronousValidationParametersResolver()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("haley-test-signing-key-that-is-at-least-32-bytes"));
        var token = CreateToken(key);
        var marker = new ResolverMarker();
        var resolverCalls = 0;
        var options = new JwtAuthOptions
        {
            ValidationParametersResolver = async (context, rawToken, cancellationToken) =>
            {
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                Assert.Same(marker, context.RequestServices.GetRequiredService<ResolverMarker>());
                Assert.Equal(token, rawToken);
                Interlocked.Increment(ref resolverCalls);
                return CreateValidationParameters(key);
            }
        };
        var handler = new TestJwtHandler(new StaticOptionsMonitor<JwtAuthOptions>(options));
        var context = CreateContext(token);
        context.RequestServices = new ServiceCollection()
            .AddSingleton(marker)
            .BuildServiceProvider();

        await handler.InitializeAsync(
            new AuthenticationScheme("TestBearer", "Test bearer", typeof(TestJwtHandler)),
            context);
        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Contains(result.Principal!.Claims, claim => claim.Value == "user-123");
        Assert.Equal(1, resolverCalls);
    }

    [Fact]
    public async Task RejectsTokenWhenResolverReturnsNoParameters()
    {
        var options = new JwtAuthOptions
        {
            ValidationParametersResolver = (_, _, _) => ValueTask.FromResult<TokenValidationParameters?>(null)
        };
        var handler = new TestJwtHandler(new StaticOptionsMonitor<JwtAuthOptions>(options));
        var context = CreateContext("header.payload.signature");

        await handler.InitializeAsync(
            new AuthenticationScheme("TestBearer", "Test bearer", typeof(TestJwtHandler)),
            context);
        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Contains("validation parameters", result.Failure?.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static DefaultHttpContext CreateContext(string token)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().BuildServiceProvider()
        };
        context.Request.Headers.Authorization = $"Bearer {token}";
        context.SetEndpoint(new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new AuthorizeAttribute()),
            "secured"));
        return context;
    }

    private static string CreateToken(SecurityKey key)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, "user-123")]),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = "haley-tests",
            Audience = "haley-consumer",
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };
        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }

    private static TokenValidationParameters CreateValidationParameters(SecurityKey key) => new()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidateIssuer = true,
        ValidIssuer = "haley-tests",
        ValidateAudience = true,
        ValidAudience = "haley-consumer",
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };

#pragma warning disable CS0618
    private sealed class TestJwtHandler(IOptionsMonitor<JwtAuthOptions> options)
        : PlainHeaderJWTHandler(
            options,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            new SystemClock());
#pragma warning restore CS0618

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable OnChange(Action<T, string?> listener) => NullDisposable.Instance;
    }

    private sealed class NullDisposable : IDisposable
    {
        internal static readonly NullDisposable Instance = new();
        public void Dispose() { }
    }

    private sealed class ResolverMarker;
}
