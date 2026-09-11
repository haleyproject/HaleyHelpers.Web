namespace Haley.Internal;

internal sealed record BrowserRefreshPayload(string RefreshToken, Guid? TenantId);
