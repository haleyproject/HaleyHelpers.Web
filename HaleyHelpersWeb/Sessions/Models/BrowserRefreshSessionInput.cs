namespace Haley.Models;

public sealed record BrowserRefreshSessionInput(
    Guid SessionId,
    Guid SubjectId,
    ReadOnlyMemory<byte> RefreshPayload,
    DateTimeOffset ExpiresAt);
