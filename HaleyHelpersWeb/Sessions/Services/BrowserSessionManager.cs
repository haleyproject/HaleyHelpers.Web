using System.Buffers.Binary;
using System.Security.Cryptography;
using Haley.Abstractions;
using Haley.Internal;
using Haley.Models;
using Haley.Security;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class BrowserSessionManager : IBrowserSessionManager
{
    private const byte AccessEnvelopeVersion = 1;
    private const int AccessHeaderLength = 1 + sizeof(long);
    private readonly IBrowserSessionDAL _store;
    private readonly BrowserSessionOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISecretEnvelopeProtector _protector;
    private readonly string _accessPurpose;
    private readonly string _refreshPurpose;

    internal BrowserSessionManager(
        IBrowserSessionDAL store,
        IOptions<BrowserSessionOptions> options,
        TimeProvider timeProvider)
    {
        _store = store;
        _options = options.Value;
        _timeProvider = timeProvider;
        var keys = _options.Protection.Keys
            .Select(key => SecretProtectionKey.FromFile(
                key.KeyId.Trim(),
                Path.IsPathFullyQualified(key.Path)
                    ? key.Path
                    : Path.GetFullPath(key.Path, AppContext.BaseDirectory),
                string.Equals(key.KeyId, _options.Protection.ActiveKeyId, StringComparison.Ordinal) ||
                string.Equals(key.Status, "active", StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        _protector = new AesGcmSecretProtector(keys, _options.Protection.ActiveKeyId);
        _accessPurpose = $"haley.browser.access:{_options.Scope}";
        _refreshPurpose = $"haley.browser.refresh:{_options.Scope}";
    }

    public string ProtectAccess(ReadOnlySpan<byte> payload, DateTimeOffset expiresAt)
    {
        if (payload.IsEmpty || payload.Length > _options.MaximumAccessPayloadBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(payload),
                $"The access payload must contain between 1 and {_options.MaximumAccessPayloadBytes} bytes.");
        }
        if (expiresAt <= _timeProvider.GetUtcNow())
        {
            throw new ArgumentOutOfRangeException(nameof(expiresAt), "The access ticket must expire in the future.");
        }

        var plaintext = new byte[AccessHeaderLength + payload.Length];
        plaintext[0] = AccessEnvelopeVersion;
        BinaryPrimitives.WriteInt64BigEndian(plaintext.AsSpan(1, sizeof(long)), expiresAt.ToUnixTimeSeconds());
        payload.CopyTo(plaintext.AsSpan(AccessHeaderLength));
        try
        {
            return WebEncoders.Base64UrlEncode(_protector.Protect(plaintext, _accessPurpose));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public bool TryUnprotectAccess(string ticket, out BrowserAccessTicket? access)
    {
        access = null;
        if (string.IsNullOrWhiteSpace(ticket) || ticket.Length > 16384) return false;
        byte[] plaintext;
        try
        {
            plaintext = _protector.Unprotect(WebEncoders.Base64UrlDecode(ticket), _accessPurpose);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return false;
        }

        try
        {
            if (plaintext.Length <= AccessHeaderLength || plaintext[0] != AccessEnvelopeVersion) return false;
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(
                BinaryPrimitives.ReadInt64BigEndian(plaintext.AsSpan(1, sizeof(long))));
            if (expiresAt <= _timeProvider.GetUtcNow()) return false;
            access = new(plaintext[AccessHeaderLength..], expiresAt);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async ValueTask<string> CreateRefreshAsync(
        BrowserRefreshSessionInput session,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (session.SessionId == Guid.Empty || session.SubjectId == Guid.Empty)
            throw new ArgumentException("Session and subject identifiers are required.", nameof(session));
        ValidateRefreshPayload(session.RefreshPayload.Span);
        var now = _timeProvider.GetUtcNow();
        if (session.ExpiresAt <= now)
            throw new ArgumentOutOfRangeException(nameof(session), "The refresh session must expire in the future.");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var handle = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(
                Math.Clamp(_options.HandleBytes, 32, 64)));
            var protectedPayload = ProtectRefresh(session.RefreshPayload.Span);
            if (await _store.CreateAsync(
                    _options.Scope,
                    Hash(handle),
                    session.SessionId,
                    session.SubjectId,
                    protectedPayload,
                    now,
                    session.ExpiresAt,
                    cancellationToken).ConfigureAwait(false))
            {
                return handle;
            }
        }

        throw new InvalidOperationException("Unable to allocate a unique browser refresh-session handle.");
    }

    public async ValueTask<BrowserRefreshLease?> AcquireRefreshAsync(
        string handle,
        CancellationToken cancellationToken = default)
    {
        if (!ValidHandle(handle)) return null;
        var now = _timeProvider.GetUtcNow();
        var leaseId = Guid.NewGuid();
        var stored = await _store.AcquireAsync(
            _options.Scope,
            Hash(handle),
            leaseId,
            now,
            now.AddSeconds(Math.Clamp(_options.LeaseSeconds, 5, 120)),
            cancellationToken).ConfigureAwait(false);
        if (stored is null) return null;

        try
        {
            return new(
                handle,
                leaseId,
                stored.SessionId,
                stored.SubjectId,
                _protector.Unprotect(stored.ProtectedPayload, _refreshPurpose),
                stored.ExpiresAt,
                stored.Version);
        }
        catch
        {
            await _store.ReleaseAsync(
                _options.Scope,
                Hash(handle),
                leaseId,
                CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<bool> CompleteRefreshAsync(
        BrowserRefreshLease lease,
        ReadOnlyMemory<byte> refreshPayload,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ValidateRefreshPayload(refreshPayload.Span);
        if (expiresAt <= _timeProvider.GetUtcNow())
            throw new ArgumentOutOfRangeException(nameof(expiresAt), "The refresh session must expire in the future.");
        return await _store.CompleteAsync(
            _options.Scope,
            Hash(lease.Handle),
            lease.LeaseId,
            lease.Version,
            ProtectRefresh(refreshPayload.Span),
            _timeProvider.GetUtcNow(),
            expiresAt,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask ReleaseRefreshAsync(
        BrowserRefreshLease lease,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        await _store.ReleaseAsync(
            _options.Scope,
            Hash(lease.Handle),
            lease.LeaseId,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<BrowserSessionRevocation?> RevokeRefreshAsync(
        string? handle,
        CancellationToken cancellationToken = default) =>
        !ValidHandle(handle)
            ? null
            : await _store.RevokeAsync(
                _options.Scope,
                Hash(handle!),
                _timeProvider.GetUtcNow(),
                cancellationToken).ConfigureAwait(false);

    public async ValueTask<int> RemoveExpiredAsync(CancellationToken cancellationToken = default) =>
        await _store.RemoveExpiredAsync(
            _options.Scope,
            _timeProvider.GetUtcNow().AddSeconds(-Math.Max(0, _options.RetentionSeconds)),
            cancellationToken).ConfigureAwait(false);

    private byte[] ProtectRefresh(ReadOnlySpan<byte> payload) =>
        _protector.Protect(payload, _refreshPurpose);

    private void ValidateRefreshPayload(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty || payload.Length > _options.MaximumRefreshPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(payload),
                $"The refresh payload must contain between 1 and {_options.MaximumRefreshPayloadBytes} bytes.");
    }

    private static byte[] Hash(string handle) =>
        SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(handle));

    private bool ValidHandle(string? handle) =>
        !string.IsNullOrWhiteSpace(handle) && handle.Length <= 512;
}
