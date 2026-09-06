namespace Haley.Utils;

public static class AdminLoginLockoutFile
{
    public static string ResolvePath(string? configuredPath, string contentRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contentRoot);
        var value = string.IsNullOrWhiteSpace(configuredPath)
            ? Models.AdminLoginLockoutOptions.DefaultStatePath
            : configuredPath.Trim();
        return Path.GetFullPath(Path.IsPathRooted(value)
            ? value
            : Path.Combine(contentRoot, value));
    }

    public static int RunResetCommand(
        string[] arguments,
        string configurationSection,
        string applicationName)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationSection);
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);
        if (arguments.Length > 1)
        {
            Console.Error.WriteLine($"Usage: {applicationName} reset-lockout [state-file]");
            return 2;
        }

        try
        {
            var contentRoot = Directory.GetCurrentDirectory();
            var configuredPath = arguments.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(configuredPath))
            {
                var configuration = ResourceUtils.GenerateConfigurationRoot(
                    ["appsettings"],
                    contentRoot);
                configuredPath = configuration[$"{configurationSection}:LoginLockoutStatePath"];
            }

            var path = ResolvePath(configuredPath, contentRoot);
            var existed = File.Exists(path);
            if (existed) File.Delete(path);

            Console.WriteLine(existed
                ? $"Admin login lockout reset: {path}"
                : $"No active admin login lockout state was found: {path}");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Unable to reset admin login lockout: {exception.Message}");
            return 1;
        }
    }
}
