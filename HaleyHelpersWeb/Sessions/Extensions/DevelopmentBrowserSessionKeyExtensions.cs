using System.Security.Cryptography;
using Haley.Models;

namespace Haley.Utils;

public static class DevelopmentBrowserSessionKeyExtensions
{
    public static void EnsureDevelopmentBrowserSessionKey(
        this IConfiguration configuration,
        IHostEnvironment environment,
        string sectionName = BrowserSessionOptions.DefaultSectionName)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);
        if (!environment.IsDevelopment()) return;

        var protection = configuration.GetSection($"{sectionName}:Protection");
        var activeKeyId = protection["ActiveKeyId"]?.Trim();
        var activeKey = protection.GetSection("Keys")
            .GetChildren()
            .FirstOrDefault(key => string.Equals(key["KeyId"]?.Trim(), activeKeyId, StringComparison.Ordinal));
        var configuredPath = activeKey?["Path"]?.Trim();
        if (string.IsNullOrWhiteSpace(activeKeyId) || string.IsNullOrWhiteSpace(configuredPath)) return;

        var path = Path.IsPathFullyQualified(configuredPath)
            ? configuredPath
            : Path.GetFullPath(configuredPath, AppContext.BaseDirectory);
        if (File.Exists(path)) return;

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(key);
        }
        catch (IOException) when (File.Exists(path))
        {
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
