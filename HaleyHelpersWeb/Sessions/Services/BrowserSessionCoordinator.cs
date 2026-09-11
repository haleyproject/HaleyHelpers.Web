using System.Security.Cryptography;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Constants;
using Haley.Internal;
using Haley.Models;

namespace Haley.Services;

public sealed class BrowserSessionCoordinator<TLoginRequest>(
    IBrowserSessionManager browserSessions,
    IBrowserIdentitySessionGateway<TLoginRequest> identity,
    ILogger<BrowserSessionCoordinator<TLoginRequest>> logger)
{
    public async ValueTask<IFeedback<BrowserSessionCookies>> LoginAsync(
        TLoginRequest request,
        Guid? tenantId,
        string? previousRefreshHandle,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken = default)
    {
        var authenticated = await identity.AuthenticateAsync(
            request,
            ipAddress,
            userAgent,
            cancellationToken).ConfigureAwait(false);
        if (!authenticated.Status || authenticated.Result is null)
            return CopyFailure(authenticated);

        if (!string.IsNullOrWhiteSpace(previousRefreshHandle))
        {
            var previous = await browserSessions.RevokeRefreshAsync(previousRefreshHandle, cancellationToken)
                .ConfigureAwait(false);
            if (previous is not null)
                await identity.RevokeAsync(previous.SessionId, cancellationToken).ConfigureAwait(false);
        }

        var session = authenticated.Result;
        var selectedTenantId = tenantId ?? session.TenantId;
        try
        {
            return Success(await CreateCookiesAsync(session, selectedTenantId, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException or JsonException)
        {
            await identity.RevokeAsync(session.SessionId, CancellationToken.None).ConfigureAwait(false);
            BrowserSessionLog.PersistenceFailed(logger, exception);
            return Failure(BrowserSessionErrorCodes.Unavailable, "The browser session could not be created.");
        }
    }

    public async ValueTask<IFeedback<BrowserSessionCookies>> RefreshAsync(
        string? refreshHandle,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshHandle))
            return Failure(BrowserSessionErrorCodes.Invalid, "The browser session is unavailable.");

        var lease = await browserSessions.AcquireRefreshAsync(refreshHandle, cancellationToken).ConfigureAwait(false);
        if (lease is null)
            return Failure(BrowserSessionErrorCodes.Busy, "The browser session is unavailable or currently refreshing.");

        var completed = false;
        try
        {
            var payload = JsonSerializer.Deserialize<BrowserRefreshPayload>(lease.RefreshPayload);
            if (payload is null || string.IsNullOrWhiteSpace(payload.RefreshToken))
            {
                await browserSessions.RevokeRefreshAsync(refreshHandle, cancellationToken).ConfigureAwait(false);
                return Failure(BrowserSessionErrorCodes.Invalid, "The browser session is invalid.");
            }

            var refreshed = await identity.RefreshAsync(payload.RefreshToken, cancellationToken).ConfigureAwait(false);
            if (!refreshed.Status || refreshed.Result is null)
            {
                await browserSessions.RevokeRefreshAsync(refreshHandle, cancellationToken).ConfigureAwait(false);
                return CopyFailure(refreshed);
            }

            var session = refreshed.Result;
            if (session.UserId != lease.SubjectId || session.SessionId != lease.SessionId)
            {
                await browserSessions.RevokeRefreshAsync(refreshHandle, cancellationToken).ConfigureAwait(false);
                await identity.RevokeAsync(session.SessionId, CancellationToken.None).ConfigureAwait(false);
                return Failure(BrowserSessionErrorCodes.Invalid, "The refreshed identity did not match the browser session.");
            }

            var refreshBytes = JsonSerializer.SerializeToUtf8Bytes(
                new BrowserRefreshPayload(session.RefreshToken, payload.TenantId));
            try
            {
                completed = await browserSessions.CompleteRefreshAsync(
                    lease,
                    refreshBytes,
                    session.RefreshExpiresAt,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(refreshBytes);
            }

            if (!completed)
            {
                await browserSessions.RevokeRefreshAsync(refreshHandle, CancellationToken.None).ConfigureAwait(false);
                await identity.RevokeAsync(session.SessionId, CancellationToken.None).ConfigureAwait(false);
                return Failure(BrowserSessionErrorCodes.Busy, "The browser session changed while it was refreshing.");
            }

            return Success(CreateCookies(session, payload.TenantId, refreshHandle));
        }
        catch (JsonException exception)
        {
            BrowserSessionLog.RefreshPayloadInvalid(logger, exception);
            await browserSessions.RevokeRefreshAsync(refreshHandle, CancellationToken.None).ConfigureAwait(false);
            return Failure(BrowserSessionErrorCodes.Invalid, "The browser session is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(lease.RefreshPayload);
            if (!completed)
                await browserSessions.ReleaseRefreshAsync(lease, CancellationToken.None).ConfigureAwait(false);
        }
    }

    public async ValueTask LogoutAsync(
        string? refreshHandle,
        CancellationToken cancellationToken = default)
    {
        var revoked = await browserSessions.RevokeRefreshAsync(refreshHandle, cancellationToken).ConfigureAwait(false);
        if (revoked is not null)
            await identity.RevokeAsync(revoked.SessionId, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<BrowserSessionCookies> CreateCookiesAsync(
        BrowserIdentitySession session,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        var refreshBytes = JsonSerializer.SerializeToUtf8Bytes(
            new BrowserRefreshPayload(session.RefreshToken, tenantId));
        string refreshHandle;
        try
        {
            refreshHandle = await browserSessions.CreateRefreshAsync(
                new BrowserRefreshSessionInput(
                    session.SessionId,
                    session.UserId,
                    refreshBytes,
                    session.RefreshExpiresAt),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(refreshBytes);
        }

        try
        {
            return CreateCookies(session, tenantId, refreshHandle);
        }
        catch
        {
            await browserSessions.RevokeRefreshAsync(refreshHandle, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private BrowserSessionCookies CreateCookies(
        BrowserIdentitySession session,
        Guid? tenantId,
        string refreshHandle)
    {
        var accessBytes = JsonSerializer.SerializeToUtf8Bytes(
            new BrowserAccessPayload(session.AccessToken, tenantId));
        try
        {
            return new(
                browserSessions.ProtectAccess(accessBytes, session.AccessExpiresAt),
                session.AccessExpiresAt,
                refreshHandle,
                session.RefreshExpiresAt,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(accessBytes);
        }
    }

    private static Feedback<BrowserSessionCookies> Success(BrowserSessionCookies cookies) =>
        new(true, "Browser session ready.", cookies)
        {
            Source = "Haley.BrowserSessions"
        };

    private static Feedback<BrowserSessionCookies> CopyFailure(IFeedback<BrowserIdentitySession> source) =>
        new(false, source.Message, default!)
        {
            Key = source.Key,
            Code = source.Code,
            Source = source.Source
        };

    private static Feedback<BrowserSessionCookies> Failure(string key, string message) =>
        new(false, message, default!)
        {
            Key = key,
            Source = "Haley.BrowserSessions"
        };
}
