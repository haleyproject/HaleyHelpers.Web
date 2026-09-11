namespace Haley.Models;

public sealed record BrowserIdentitySession(
    Guid UserId,
    Guid SessionId,
    string DisplayName,
    string? Username,
    string AccessToken,
    DateTimeOffset AccessExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshExpiresAt,
    Guid? TenantId = null);
