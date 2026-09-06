using Haley.Models;
using Haley.Utils;
using Xunit;

namespace HaleyHelpersWeb.Tests;

public sealed class AdminLoginLockoutServiceTests
{
    [Fact]
    public async Task LockoutPersistsAndExpiresUsingConfiguredClock()
    {
        var root = CreateTemporaryRoot();
        try
        {
            var options = new AdminLoginLockoutOptions
            {
                MaxFailedLoginAttempts = 2,
                LoginLockoutMinutes = 5,
                LoginLockoutStatePath = "State/admin-lockout.json"
            };
            var monitor = new StaticOptionsMonitor<AdminLoginLockoutOptions>(options);
            var environment = new TestHostEnvironment(root);
            var clock = new TestTimeProvider(new DateTimeOffset(2026, 9, 6, 12, 0, 0, TimeSpan.Zero));
            var firstInstance = new AdminLoginLockoutService(monitor, environment, clock);

            var firstFailure = await firstInstance.RecordFailureAsync();
            var secondFailure = await firstInstance.RecordFailureAsync();

            Assert.False(firstFailure.IsLocked);
            Assert.True(secondFailure.IsLocked);
            Assert.True(File.Exists(Path.Combine(root, "State", "admin-lockout.json")));

            var restartedInstance = new AdminLoginLockoutService(monitor, environment, clock);
            Assert.True((await restartedInstance.GetStatusAsync()).IsLocked);

            clock.Advance(TimeSpan.FromMinutes(6));
            var expired = await restartedInstance.GetStatusAsync();
            Assert.False(expired.IsLocked);
            Assert.Equal(0, expired.FailedAttempts);
            Assert.False(File.Exists(Path.Combine(root, "State", "admin-lockout.json")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ResetRemovesPersistedFailures()
    {
        var root = CreateTemporaryRoot();
        try
        {
            var options = new AdminLoginLockoutOptions
            {
                LoginLockoutStatePath = "State/admin-lockout.json"
            };
            var service = new AdminLoginLockoutService(
                new StaticOptionsMonitor<AdminLoginLockoutOptions>(options),
                new TestHostEnvironment(root),
                TimeProvider.System);

            await service.RecordFailureAsync();
            await service.ResetAsync();

            var status = await service.GetStatusAsync();
            Assert.Equal(0, status.FailedAttempts);
            Assert.False(status.IsLocked);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ResetCommandRemovesExplicitStateFile()
    {
        var root = CreateTemporaryRoot();
        try
        {
            var path = Path.Combine(root, "admin-lockout.json");
            File.WriteAllText(path, "{}");

            var exitCode = AdminLoginLockoutFile.RunResetCommand(
                [path],
                "Unused:Section",
                "Test.Admin.Host");

            Assert.Equal(0, exitCode);
            Assert.False(File.Exists(path));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTemporaryRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"haley-admin-security-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        return root;
    }
}
