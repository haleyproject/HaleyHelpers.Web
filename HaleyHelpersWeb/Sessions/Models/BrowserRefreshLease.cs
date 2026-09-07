namespace Haley.Models;

public sealed record BrowserRefreshLease(
    string Handle,
    Guid LeaseId,
    Guid SessionId,
    Guid SubjectId,
    byte[] RefreshPayload,
    DateTimeOffset ExpiresAt,
    long Version);
