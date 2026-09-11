namespace Haley.Internal;

internal sealed record BrowserAccessPayload(string AccessToken, Guid? TenantId);
