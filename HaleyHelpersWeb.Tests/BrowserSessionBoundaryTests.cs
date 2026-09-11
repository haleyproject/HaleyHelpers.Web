using System.Text.Json;
using Haley.Abstractions;
using Haley.Constants;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace HaleyHelpersWeb.Tests;

public sealed class BrowserSessionBoundaryTests
{
    [Fact]
    public async Task CoordinatorCreatesProtectedAccessAndServerSideRefreshSession()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var manager = new StubBrowserSessionManager();
        var identity = new StubIdentityGateway(new BrowserIdentitySession(
            userId,
            sessionId,
            "Test User",
            "tester",
            "access-token",
            now.AddMinutes(5),
            "refresh-token",
            now.AddHours(8),
            tenantId));
        var coordinator = new BrowserSessionCoordinator<string>(
            manager,
            identity,
            NullLogger<BrowserSessionCoordinator<string>>.Instance);

        var result = await coordinator.LoginAsync("login", null, null, "127.0.0.1", "test-agent");

        Assert.True(result.Status);
        Assert.NotNull(result.Result);
        Assert.Equal("protected-access", result.Result.AccessTicket);
        Assert.Equal("refresh-handle", result.Result.RefreshHandle);
        Assert.Equal(sessionId, manager.CreatedRefreshSession?.SessionId);
        Assert.Equal(userId, manager.CreatedRefreshSession?.SubjectId);
        AssertPayload(manager.AccessPayload, "access-token", tenantId);
        AssertPayload(manager.CreatedRefreshSession?.RefreshPayload.ToArray(), "refresh-token", tenantId);
    }

    [Fact]
    public async Task MiddlewareRejectsUnsafeCookieRequestWithoutMatchingAntiforgeryToken()
    {
        var manager = new StubBrowserSessionManager();
        var pipeline = BuildPipeline(manager, _ => Task.CompletedTask);
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Headers.Cookie = "test.access=ticket";
        context.Response.Body = new MemoryStream();

        await pipeline(context);

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var document = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal(
            BrowserSessionErrorCodes.AntiforgeryRejected,
            document.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task MiddlewareHydratesAuthorizationAndSharedContextItems()
    {
        var tenantId = Guid.NewGuid();
        var manager = new StubBrowserSessionManager
        {
            UnprotectedAccess = new BrowserAccessTicket(
                JsonSerializer.SerializeToUtf8Bytes(new
                {
                    AccessToken = "identity-token",
                    TenantId = tenantId
                }),
                DateTimeOffset.UtcNow.AddMinutes(5))
        };
        var reached = false;
        var pipeline = BuildPipeline(manager, _ =>
        {
            reached = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Headers.Cookie = "test.access=ticket";

        await pipeline(context);

        Assert.True(reached);
        Assert.Equal("TestScheme identity-token", context.Request.Headers.Authorization);
        Assert.Equal(true, context.Items[BrowserSessionContextItemKeys.CookieAuthentication]);
        Assert.Equal(tenantId, context.Items[BrowserSessionContextItemKeys.TenantId]);
        Assert.All(manager.UnprotectedAccess.Payload, value => Assert.Equal(0, value));
    }

    [Fact]
    public void DevelopmentKeyHelperCreatesConfiguredKeyOnce()
    {
        var root = Path.Combine(Path.GetTempPath(), $"haley-browser-session-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "browser-session.key");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Haley:BrowserSessions:Protection:ActiveKeyId"] = "test-key",
                    ["Haley:BrowserSessions:Protection:Keys:0:KeyId"] = "test-key",
                    ["Haley:BrowserSessions:Protection:Keys:0:Path"] = path,
                    ["Haley:BrowserSessions:Protection:Keys:0:Status"] = "active"
                })
                .Build();
            var environment = new TestHostEnvironment(root);

            configuration.EnsureDevelopmentBrowserSessionKey(environment);
            var original = File.ReadAllBytes(path);
            configuration.EnsureDevelopmentBrowserSessionKey(environment);

            Assert.Equal(32, original.Length);
            Assert.Equal(original, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void RequestValueHelpersTakeOneHeaderAndParseGuidRoutes()
    {
        var routeId = Guid.NewGuid();
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Test-Secret"] = "  secret  ";
        context.Request.RouteValues["id"] = routeId.ToString();

        var tookHeader = context.Request.TryTakeSingleHeaderValue("X-Test-Secret", out var value);
        var parsedRoute = context.Request.TryGetGuidRouteValue("id", out var parsed);

        Assert.True(tookHeader);
        Assert.Equal("secret", value);
        Assert.False(context.Request.Headers.ContainsKey("X-Test-Secret"));
        Assert.True(parsedRoute);
        Assert.Equal(routeId, parsed);
    }

    [Fact]
    public void FeedbackHelperPreservesValidFailureStatus()
    {
        var feedback = new Feedback<string>(false, "Unavailable.", default!)
        {
            Code = StatusCodes.Status503ServiceUnavailable,
            Key = "test.unavailable"
        };

        var result = feedback.ToMinimalApiResult();

        Assert.Equal(
            StatusCodes.Status503ServiceUnavailable,
            Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode);
    }

    private static RequestDelegate BuildPipeline(
        IBrowserSessionManager manager,
        RequestDelegate terminal)
    {
        var services = new ServiceCollection()
            .AddSingleton(manager)
            .AddSingleton<IOptions<BrowserSessionBoundaryOptions>>(Options.Create(new BrowserSessionBoundaryOptions
            {
                AccessCookieName = "test.access",
                RefreshCookieName = "test.refresh",
                AntiforgeryCookieName = "test.csrf",
                AntiforgeryHeaderName = "X-Test-CSRF",
                AuthenticationScheme = "TestScheme",
                RequireHttps = false
            }))
            .BuildServiceProvider();
        var application = new ApplicationBuilder(services);
        application.UseHaleyBrowserSessionBoundary();
        application.Run(terminal);
        return application.Build();
    }

    private static void AssertPayload(byte[]? payload, string token, Guid tenantId)
    {
        Assert.NotNull(payload);
        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        var value = root.TryGetProperty("AccessToken", out var accessToken)
            ? accessToken.GetString()
            : root.GetProperty("RefreshToken").GetString();
        Assert.Equal(token, value);
        Assert.Equal(tenantId, root.GetProperty("TenantId").GetGuid());
    }

    private sealed class StubIdentityGateway(BrowserIdentitySession session)
        : IBrowserIdentitySessionGateway<string>
    {
        public ValueTask<IFeedback<BrowserIdentitySession>> AuthenticateAsync(
            string request,
            string? ipAddress,
            string? userAgent,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IFeedback<BrowserIdentitySession>>(
                new Feedback<BrowserIdentitySession>(true, "Authenticated.", session));

        public ValueTask<IFeedback<BrowserIdentitySession>> RefreshAsync(
            string refreshToken,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IFeedback<BrowserIdentitySession>>(
                new Feedback<BrowserIdentitySession>(true, "Refreshed.", session));

        public ValueTask RevokeAsync(Guid sessionId, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
    }

    private sealed class StubBrowserSessionManager : IBrowserSessionManager
    {
        public byte[]? AccessPayload { get; private set; }

        public BrowserRefreshSessionInput? CreatedRefreshSession { get; private set; }

        public BrowserAccessTicket? UnprotectedAccess { get; init; }

        public string ProtectAccess(ReadOnlySpan<byte> payload, DateTimeOffset expiresAt)
        {
            AccessPayload = payload.ToArray();
            return "protected-access";
        }

        public bool TryUnprotectAccess(string ticket, out BrowserAccessTicket? access)
        {
            access = UnprotectedAccess;
            return access is not null;
        }

        public ValueTask<string> CreateRefreshAsync(
            BrowserRefreshSessionInput session,
            CancellationToken cancellationToken = default)
        {
            CreatedRefreshSession = session with { RefreshPayload = session.RefreshPayload.ToArray() };
            return ValueTask.FromResult("refresh-handle");
        }

        public ValueTask<BrowserRefreshLease?> AcquireRefreshAsync(
            string handle,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<BrowserRefreshLease?>(null);

        public ValueTask<bool> CompleteRefreshAsync(
            BrowserRefreshLease lease,
            ReadOnlyMemory<byte> refreshPayload,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(true);

        public ValueTask ReleaseRefreshAsync(
            BrowserRefreshLease lease,
            CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask<BrowserSessionRevocation?> RevokeRefreshAsync(
            string? handle,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<BrowserSessionRevocation?>(null);

        public ValueTask<int> RemoveExpiredAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(0);
    }
}
