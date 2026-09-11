using Haley.Models;

namespace Haley.Abstractions;

public interface IBrowserIdentitySessionGateway<in TLoginRequest>
{
    ValueTask<IFeedback<BrowserIdentitySession>> AuthenticateAsync(
        TLoginRequest request,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken = default);

    ValueTask<IFeedback<BrowserIdentitySession>> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);

    ValueTask RevokeAsync(Guid sessionId, CancellationToken cancellationToken = default);
}
