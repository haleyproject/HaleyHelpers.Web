using Haley.Abstractions;
using Haley.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Haley.Services;

internal sealed class BrowserSessionCleanupHostedService(
    IBrowserSessionManager sessions,
    IOptions<BrowserSessionOptions> options,
    ILogger<BrowserSessionCleanupHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Clamp(options.Value.CleanupSeconds, 60, 86400));
        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                var removed = await sessions.RemoveExpiredAsync(stoppingToken).ConfigureAwait(false);
                if (removed > 0)
                {
                    logger.LogInformation(
                        "Removed {RemovedCount} expired Haley browser-session records for scope {SessionScope}.",
                        removed,
                        options.Value.Scope);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Haley browser-session cleanup failed.");
            }
        }
    }
}
