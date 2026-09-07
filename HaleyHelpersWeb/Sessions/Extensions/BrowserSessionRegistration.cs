using Haley.Abstractions;
using Haley.Internal;
using Haley.Models;
using Haley.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Haley.Utils;

public static class BrowserSessionRegistration
{
    public static IServiceCollection AddHaleyBrowserSessions(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = BrowserSessionOptions.DefaultSectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        services.AddOptions<BrowserSessionOptions>()
            .Bind(configuration.GetSection(sectionName))
            .Validate(Valid, "Haley browser-session adapter, scope, limits, and protection-key configuration are invalid.")
            .ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IBrowserSessionDAL, MariaBrowserSessionDAL>();
        services.TryAddSingleton<IBrowserSessionManager>(provider =>
            new BrowserSessionManager(
                provider.GetRequiredService<IBrowserSessionDAL>(),
                provider.GetRequiredService<IOptions<BrowserSessionOptions>>(),
                provider.GetRequiredService<TimeProvider>()));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, BrowserSessionDatabaseHostedService>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, BrowserSessionCleanupHostedService>());
        return services;
    }

    private static bool Valid(BrowserSessionOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Adapter) ||
            string.IsNullOrWhiteSpace(options.Scope) || options.Scope.Length > 80 ||
            options.HandleBytes is < 32 or > 64 ||
            options.LeaseSeconds is < 5 or > 120 ||
            options.CleanupSeconds is < 60 or > 86400 ||
            options.RetentionSeconds < 0 ||
            options.MaximumAccessPayloadBytes is < 256 or > 12288 ||
            options.MaximumRefreshPayloadBytes is < 256 or > 65536 ||
            string.IsNullOrWhiteSpace(options.Protection.ActiveKeyId) ||
            options.Protection.Keys.Count == 0)
        {
            return false;
        }

        var keys = options.Protection.Keys;
        return keys.All(key =>
                   !string.IsNullOrWhiteSpace(key.KeyId) &&
                   !string.IsNullOrWhiteSpace(key.Path)) &&
               keys.Select(key => key.KeyId.Trim()).Distinct(StringComparer.Ordinal).Count() == keys.Count &&
               keys.Count(key =>
                   string.Equals(key.KeyId, options.Protection.ActiveKeyId, StringComparison.Ordinal) ||
                   string.Equals(key.Status, "active", StringComparison.OrdinalIgnoreCase)) == 1;
    }
}
