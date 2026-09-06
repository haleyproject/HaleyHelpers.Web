namespace Haley.Models;

public sealed record AdminLoginLockoutStatus(
    bool IsLocked,
    int FailedAttempts,
    int MaximumAttempts,
    DateTimeOffset? LockedUntil);
