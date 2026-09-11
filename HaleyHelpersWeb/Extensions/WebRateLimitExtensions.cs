using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Haley.Utils;

public static class WebRateLimitExtensions
{
    public static IServiceCollection AddFixedWindowIpRateLimit(
        this IServiceCollection services,
        string policyName,
        int permitLimit,
        TimeSpan? window = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        if (permitLimit < 1) throw new ArgumentOutOfRangeException(nameof(permitLimit));
        var effectiveWindow = window ?? TimeSpan.FromMinutes(1);
        if (effectiveWindow <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(window));

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(policyName, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = permitLimit,
                        QueueLimit = 0,
                        Window = effectiveWindow
                    }));
        });
        return services;
    }
}
