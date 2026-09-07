using System.Text;
using Haley.Abstractions;
using Haley.Models;
using Haley.Utils;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Haley.Services;

internal sealed class BrowserSessionDatabaseHostedService(
    IAdapterGateway gateway,
    IOptions<BrowserSessionOptions> options,
    ILogger<BrowserSessionDatabaseHostedService> logger) : IHostedService
{
    private const string SchemaResource = "Haley.BrowserSessions.Database.MariaDB.schema.sql";

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!options.Value.Initialize) return;
        var content = ResourceUtils.GetEmbeddedResource(
            SchemaResource,
            typeof(BrowserSessionDatabaseHostedService).Assembly)
            ?? throw new InvalidOperationException($"Embedded browser-session schema '{SchemaResource}' was not found.");
        var result = await gateway.BootstrapDatabaseAsync(
            new DatabaseBootstrapArgs(options.Value.Adapter)
            {
                SqlContent = Encoding.UTF8.GetString(content),
                LockKey = $"haley-browser-session:{options.Value.Scope}"
            },
            cancellationToken).ConfigureAwait(false);
        if (!result.Status)
        {
            throw new InvalidOperationException(
                $"Haley browser-session database initialization failed. {result.Message}");
        }
        logger.LogInformation(
            "Initialized the Haley browser-session schema for scope {SessionScope}.",
            options.Value.Scope);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
