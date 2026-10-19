using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Builder;

namespace Haley.Utils;

public static class WebRateLimitExtensions
{
    /// <summary>Applies a configured allowance after binding, when the subject is in a JSON/form request.</summary>
    public static RouteHandlerBuilder WithConfiguredFixedWindowRateLimit(
        this RouteHandlerBuilder endpoint, string policyName,
        Func<EndpointFilterInvocationContext, ValueTask<string?>>? subject = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        return endpoint.AddEndpointFilter(async (invocation, next) =>
        {
            var context = invocation.HttpContext;
            var limiter = context.RequestServices.GetRequiredService<FixedWindowRequestRateLimiter>();
            var settings = limiter.GetOptions(policyName);
            var user = settings.Enabled && string.Equals(settings.Scope, RequestRateLimitOptions.IpUserScope, StringComparison.OrdinalIgnoreCase)
                && subject is not null ? await subject(invocation).ConfigureAwait(false) : null;
            using var lease = limiter.AttemptAcquire(context, policyName, subject is null ? null : user ?? string.Empty);
            return lease.IsAcquired ? await next(invocation).ConfigureAwait(false) : FixedWindowRequestRateLimiter.Rejection(context, lease);
        });
    }

    /// <summary>Registers a named, validated policy whose settings can be changed through configuration.</summary>
    public static IServiceCollection AddConfiguredFixedWindowRateLimit(
        this IServiceCollection services,
        string policyName,
        IConfigurationSection configuration,
        Action<RequestRateLimitOptions>? defaults = null,
        Func<HttpContext, string?>? subject = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentNullException.ThrowIfNull(configuration);
        var options = services.AddOptions<RequestRateLimitOptions>(policyName);
        if (defaults is not null) options.Configure(defaults);
        options.Bind(configuration).Validate(value => value.IsValid(),
            $"{configuration.Path} requires PermitLimit 1..1000000, WindowSeconds 1..86400 and Scope ip or ip-user.").ValidateOnStart();
        services.TryAddSingleton<FixedWindowRequestRateLimiter>();
        services.AddRateLimiter(limits =>
        {
            limits.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limits.OnRejected = async (rejection, _) =>
                await FixedWindowRequestRateLimiter.Rejection(rejection.HttpContext, rejection.Lease)
                    .ExecuteAsync(rejection.HttpContext).ConfigureAwait(false);
            limits.AddPolicy(policyName, context => context.RequestServices.GetRequiredService<FixedWindowRequestRateLimiter>()
                .GetPartition(context, policyName, subject?.Invoke(context)));
        });
        return services;
    }

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
