namespace Haley.Models;

internal sealed class AdminLoginLockoutState
{
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
}
