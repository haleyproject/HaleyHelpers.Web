namespace Haley.Internal;

internal sealed record StoredBrowserRefreshSession(
    Guid SessionId,
    Guid SubjectId,
    byte[] ProtectedPayload,
    DateTimeOffset ExpiresAt,
    long Version);
