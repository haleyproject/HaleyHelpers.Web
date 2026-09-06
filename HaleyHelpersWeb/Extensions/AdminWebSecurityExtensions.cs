using System.Threading.RateLimiting;
using Haley.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Haley.Utils;

public static class AdminWebSecurityExtensions
{
    public static IServiceCollection AddAdminLoginLockout(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.AddOptions<AdminLoginLockoutOptions>()
            .Bind(configuration.GetSection(sectionName))
            .Validate(
                static options => options.MaxFailedLoginAttempts is >= 1 and <= 100 &&
                                  options.LoginLockoutMinutes is >= 1 and <= 1_440 &&
                                  !string.IsNullOrWhiteSpace(options.LoginLockoutStatePath),
                "Admin login lockout settings are invalid.")
            .ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<AdminLoginLockoutService>();
        return services;
    }

    public static IServiceCollection AddAdminAntiforgery(
        this IServiceCollection services,
        string cookieName,
        string headerName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(cookieName);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerName);

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = cookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.HeaderName = headerName;
        });
        return services;
    }

    public static IServiceCollection AddAdminLoginRateLimit(
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

    public static IApplicationBuilder UseAdminSecurityHeaders(
        this IApplicationBuilder app,
        Action<AdminSecurityHeaderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        var options = new AdminSecurityHeaderOptions();
        configure?.Invoke(options);
        if (string.IsNullOrWhiteSpace(options.ContentSecurityPolicy))
            throw new ArgumentException("Admin Content-Security-Policy cannot be empty.", nameof(configure));

        return app.Use(async (context, next) =>
        {
            context.Response.Headers.ContentSecurityPolicy = options.ContentSecurityPolicy;
            context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.Headers.XFrameOptions = "DENY";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers.CacheControl = context.Request.Path.StartsWithSegments(
                options.ApiPathPrefix)
                ? "no-store"
                : "no-cache";
            await next(context).ConfigureAwait(false);
        });
    }
}
