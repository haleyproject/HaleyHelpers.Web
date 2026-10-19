using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Haley.Models;
using Haley.Enums;
using Haley.Utils;
using Microsoft.Extensions.Options;

namespace Haley.Services;

/// <summary>Shared partition construction for middleware policies and filters with bound request subjects.</summary>
public sealed class FixedWindowRequestRateLimiter : IDisposable
{
    private readonly IOptionsMonitor<RequestRateLimitOptions> _options;
    private readonly PartitionedRateLimiter<SubjectRequest> _limiter;

    public FixedWindowRequestRateLimiter(IOptionsMonitor<RequestRateLimitOptions> options)
    {
        _options = options;
        _limiter = PartitionedRateLimiter.Create<SubjectRequest, string>(request =>
            GetPartition(request.Context, request.Policy, request.Subject));
    }

    public RequestRateLimitOptions GetOptions(string policy) => _options.Get(policy);

    public RateLimitPartition<string> GetPartition(HttpContext context, string policy, string? subject = null)
    {
        var settings = GetOptions(policy);
        if (!settings.Enabled) return RateLimitPartition.GetNoLimiter(policy + ":disabled");
        if (!settings.IsValid()) throw new OptionsValidationException(policy, typeof(RequestRateLimitOptions),
            ["Request rate limit requires a positive permit limit/window and scope ip or ip-user."]);
        var address = context.Connection.RemoteIpAddress;
        var ip = address is null ? "unknown" : address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();
        var scope = settings.Scope.ToLowerInvariant();
        subject ??= AuthenticatedSubject(context);
        var user = scope == "ip-user" && !string.IsNullOrWhiteSpace(subject)
            ? HashUtils.ComputeHash(subject.Trim(), HashMethod.Sha256) : "anonymous";
        // Including settings in the key starts a fresh, correctly configured partition after a reload.
        var key = $"{policy}:{settings.PermitLimit}:{settings.WindowSeconds}:{scope}:{ip}:{user}";
        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = settings.PermitLimit,
            Window = TimeSpan.FromSeconds(settings.WindowSeconds),
            AutoReplenishment = true,
            QueueLimit = 0
        });
    }

    public RateLimitLease AttemptAcquire(HttpContext context, string policy, string? subject = null) =>
        _limiter.AttemptAcquire(new SubjectRequest(context, policy, subject));

    public static string? AuthenticatedSubject(HttpContext context) => context.User.Identity?.IsAuthenticated == true
        ? context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? context.User.FindFirstValue("sub") ?? context.User.Identity.Name
        : null;

    public static IResult Rejection(HttpContext context, RateLimitLease lease)
    {
        var seconds = lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
            ? Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)) : RequestRateLimitOptions.DefaultWindowSeconds;
        context.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests,
            title: "Request rate limit exceeded.", detail: $"Too many requests. Retry after {seconds} seconds.",
            extensions: new Dictionary<string, object?> { ["code"] = "rate_limit_exceeded", ["retryAfterSeconds"] = seconds });
    }

    public void Dispose() => _limiter.Dispose();

    private sealed record SubjectRequest(HttpContext Context, string Policy, string? Subject);
}
