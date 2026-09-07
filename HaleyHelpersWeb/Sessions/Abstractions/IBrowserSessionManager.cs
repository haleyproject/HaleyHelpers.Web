using Haley.Models;

namespace Haley.Abstractions;

public interface IBrowserSessionManager
{
    string ProtectAccess(ReadOnlySpan<byte> payload, DateTimeOffset expiresAt);

    bool TryUnprotectAccess(string ticket, out BrowserAccessTicket? access);

    ValueTask<string> CreateRefreshAsync(
        BrowserRefreshSessionInput session,
        CancellationToken cancellationToken = default);

    ValueTask<BrowserRefreshLease?> AcquireRefreshAsync(
        string handle,
        CancellationToken cancellationToken = default);

    ValueTask<bool> CompleteRefreshAsync(
        BrowserRefreshLease lease,
        ReadOnlyMemory<byte> refreshPayload,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);

    ValueTask ReleaseRefreshAsync(
        BrowserRefreshLease lease,
        CancellationToken cancellationToken = default);

    ValueTask<BrowserSessionRevocation?> RevokeRefreshAsync(
        string? handle,
        CancellationToken cancellationToken = default);

    ValueTask<int> RemoveExpiredAsync(CancellationToken cancellationToken = default);
}
