using Haley.Models;

namespace Haley.Internal;

internal interface IBrowserSessionDAL
{
    ValueTask<bool> CreateAsync(
        string scope,
        byte[] handleHash,
        Guid sessionId,
        Guid subjectId,
        byte[] protectedPayload,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    ValueTask<StoredBrowserRefreshSession?> AcquireAsync(
        string scope,
        byte[] handleHash,
        Guid leaseId,
        DateTimeOffset acquiredAt,
        DateTimeOffset leaseExpiresAt,
        CancellationToken cancellationToken);

    ValueTask<bool> CompleteAsync(
        string scope,
        byte[] handleHash,
        Guid leaseId,
        long version,
        byte[] protectedPayload,
        DateTimeOffset accessedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    ValueTask ReleaseAsync(
        string scope,
        byte[] handleHash,
        Guid leaseId,
        CancellationToken cancellationToken);

    ValueTask<BrowserSessionRevocation?> RevokeAsync(
        string scope,
        byte[] handleHash,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken);

    ValueTask<int> RemoveExpiredAsync(
        string scope,
        DateTimeOffset removeBefore,
        CancellationToken cancellationToken);
}
