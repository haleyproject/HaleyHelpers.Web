namespace Haley.Models;

public sealed class AdminLoginLockoutOptions
{
    public const string DefaultStatePath = "State/admin-login-lockout.json";

    public int MaxFailedLoginAttempts { get; set; } = 10;
    public int LoginLockoutMinutes { get; set; } = 10;
    public string LoginLockoutStatePath { get; set; } = DefaultStatePath;
}
