using Haley.Abstractions;
using Haley.Middleware;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Haley.Utils;

public static class BrowserSessionBoundaryRegistration
{
    public static IServiceCollection AddHaleyBrowserSessionBoundary<TLoginRequest>(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<BrowserSessionBoundaryOptions>? configure = null,
        string sectionName = BrowserSessionBoundaryOptions.DefaultSectionName,
        string sessionSectionName = BrowserSessionOptions.DefaultSectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionSectionName);

        services.AddHaleyBrowserSessions(configuration, sessionSectionName);

        var builder = services.AddOptions<BrowserSessionBoundaryOptions>()
            .Bind(configuration.GetSection(sectionName));
        if (configure is not null) builder.Configure(configure);
        builder
            .Validate(Valid, "Haley browser-session boundary cookie, antiforgery, and authentication settings are invalid.")
            .ValidateOnStart();

        services.TryAddScoped<BrowserSessionCoordinator<TLoginRequest>>();
        services.TryAddScoped<BrowserSessionCookieWriter>();
        return services;
    }

    public static IApplicationBuilder UseHaleyBrowserSessionBoundary(this IApplicationBuilder application)
    {
        ArgumentNullException.ThrowIfNull(application);
        return application.UseMiddleware<BrowserSessionBoundaryMiddleware>();
    }

    private static bool Valid(BrowserSessionBoundaryOptions options)
    {
        var cookieNames = new[]
        {
            options.AccessCookieName,
            options.RefreshCookieName,
            options.AntiforgeryCookieName
        };
        return cookieNames.All(name => !string.IsNullOrWhiteSpace(name)) &&
               cookieNames.Distinct(StringComparer.Ordinal).Count() == cookieNames.Length &&
               !string.IsNullOrWhiteSpace(options.AntiforgeryHeaderName) &&
               !string.IsNullOrWhiteSpace(options.AuthenticationScheme);
    }
}
