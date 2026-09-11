using Haley.Models;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class BrowserSessionCookieWriter(IOptions<BrowserSessionBoundaryOptions> options)
{
    private readonly BrowserSessionBoundaryOptions _options = options.Value;

    public bool CanIssue(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return !_options.RequireHttps || request.IsHttps;
    }

    public void Append(HttpResponse response, BrowserSessionCookies cookies)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(cookies);
        response.Cookies.Append(
            _options.AccessCookieName,
            cookies.AccessTicket,
            Cookie(httpOnly: true, cookies.AccessExpiresAt));
        response.Cookies.Append(
            _options.RefreshCookieName,
            cookies.RefreshHandle,
            Cookie(httpOnly: true, cookies.RefreshExpiresAt));
        response.Cookies.Append(
            _options.AntiforgeryCookieName,
            cookies.AntiforgeryToken,
            Cookie(httpOnly: false, cookies.RefreshExpiresAt));
    }

    public void Delete(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Cookies.Delete(_options.AccessCookieName, Cookie(httpOnly: true));
        response.Cookies.Delete(_options.RefreshCookieName, Cookie(httpOnly: true));
        response.Cookies.Delete(_options.AntiforgeryCookieName, Cookie(httpOnly: false));
    }

    private CookieOptions Cookie(bool httpOnly, DateTimeOffset? expiresAt = null) => new()
    {
        HttpOnly = httpOnly,
        Secure = _options.RequireHttps,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        IsEssential = true,
        Expires = expiresAt
    };
}
