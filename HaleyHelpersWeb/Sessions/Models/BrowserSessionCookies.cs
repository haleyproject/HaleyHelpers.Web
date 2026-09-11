namespace Haley.Models;

public sealed record BrowserSessionCookies(
    string AccessTicket,
    DateTimeOffset AccessExpiresAt,
    string RefreshHandle,
    DateTimeOffset RefreshExpiresAt,
    string AntiforgeryToken);
