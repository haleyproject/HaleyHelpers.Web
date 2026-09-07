using Haley.Abstractions;
using Haley.Internal;
using Haley.Models;
using Haley.Utils;
using Microsoft.Extensions.Options;
using static Haley.Internal.BrowserSessionFields;

namespace Haley.Services;

internal sealed class MariaBrowserSessionDAL(
    IAdapterGateway gateway,
    IOptions<BrowserSessionOptions> options) : DALUtilBase(gateway, options.Value.Adapter), IBrowserSessionDAL
{
    public async ValueTask<bool> CreateAsync(
        string scope,
        byte[] handleHash,
        Guid sessionId,
        Guid subjectId,
        byte[] protectedPayload,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken) =>
        await ExecAsync(
            BrowserSessionQueries.Insert,
            new(cancellationToken),
            (Scope, scope),
            (HandleHash, handleHash),
            (SessionUid, sessionId.ToByteArray()),
            (SubjectUid, subjectId.ToByteArray()),
            (Payload, protectedPayload),
            (CreatedAt, createdAt.UtcDateTime),
            (ExpiresAt, expiresAt.UtcDateTime)).ConfigureAwait(false) == 1;

    public async ValueTask<StoredBrowserRefreshSession?> AcquireAsync(
        string scope,
        byte[] handleHash,
        Guid leaseId,
        DateTimeOffset acquiredAt,
        DateTimeOffset leaseExpiresAt,
        CancellationToken cancellationToken)
    {
        var load = new DbExecutionLoad(cancellationToken);
        if (await ExecAsync(
                BrowserSessionQueries.Acquire,
                load,
                (Scope, scope),
                (HandleHash, handleHash),
                (LeaseUid, leaseId.ToByteArray()),
                (LeaseExpiresAt, leaseExpiresAt.UtcDateTime),
                (AccessedAt, acquiredAt.UtcDateTime)).ConfigureAwait(false) != 1)
        {
            return null;
        }

        var row = await RowAsync(
            BrowserSessionQueries.FindLease,
            load,
            (Scope, scope),
            (HandleHash, handleHash),
            (LeaseUid, leaseId.ToByteArray())).ConfigureAwait(false);
        return row is null
            ? null
            : new(
                new Guid((byte[])row["session_uid"]),
                new Guid((byte[])row["subject_uid"]),
                (byte[])row["payload"],
                AsUtc((DateTime)row["expires_at"]),
                Convert.ToInt64(row["version"]));
    }

    public async ValueTask<bool> CompleteAsync(
        string scope,
        byte[] handleHash,
        Guid leaseId,
        long version,
        byte[] protectedPayload,
        DateTimeOffset accessedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken) =>
        await ExecAsync(
            BrowserSessionQueries.Complete,
            new(cancellationToken),
            (Scope, scope),
            (HandleHash, handleHash),
            (LeaseUid, leaseId.ToByteArray()),
            (RecordVersion, version),
            (Payload, protectedPayload),
            (AccessedAt, accessedAt.UtcDateTime),
            (ExpiresAt, expiresAt.UtcDateTime)).ConfigureAwait(false) == 1;

    public async ValueTask ReleaseAsync(
        string scope,
        byte[] handleHash,
        Guid leaseId,
        CancellationToken cancellationToken) =>
        _ = await ExecAsync(
            BrowserSessionQueries.Release,
            new(cancellationToken),
            (Scope, scope),
            (HandleHash, handleHash),
            (LeaseUid, leaseId.ToByteArray())).ConfigureAwait(false);

    public async ValueTask<BrowserSessionRevocation?> RevokeAsync(
        string scope,
        byte[] handleHash,
        DateTimeOffset revokedAt,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = new DbExecutionLoad(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(
                    BrowserSessionQueries.FindForRevoke,
                    load,
                    (Scope, scope),
                    (HandleHash, handleHash)).ConfigureAwait(false);
                if (row is null)
                {
                    transaction.Rollback();
                    return null;
                }

                if (await ExecAsync(
                        BrowserSessionQueries.Revoke,
                        load,
                        (Scope, scope),
                        (HandleHash, handleHash),
                        (RevokedAt, revokedAt.UtcDateTime)).ConfigureAwait(false) != 1)
                {
                    transaction.Rollback();
                    return null;
                }

                transaction.Commit();
                return new(
                    new Guid((byte[])row["session_uid"]),
                    new Guid((byte[])row["subject_uid"]));
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }

    public async ValueTask<int> RemoveExpiredAsync(
        string scope,
        DateTimeOffset removeBefore,
        CancellationToken cancellationToken) =>
        await ExecAsync(
            BrowserSessionQueries.RemoveExpired,
            new(cancellationToken),
            (Scope, scope),
            (RemoveBefore, removeBefore.UtcDateTime)).ConfigureAwait(false);

    private static DateTimeOffset AsUtc(DateTime value) =>
        new(DateTime.SpecifyKind(value, DateTimeKind.Utc));
}
