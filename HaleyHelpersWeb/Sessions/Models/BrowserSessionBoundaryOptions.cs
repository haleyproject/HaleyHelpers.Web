namespace Haley.Models;

public sealed class BrowserSessionBoundaryOptions
{
    public const string DefaultSectionName = "Haley:BrowserSessions:Boundary";

    public string AccessCookieName { get; set; } = "haley.access";

    public string RefreshCookieName { get; set; } = "haley.refresh";

    public string AntiforgeryCookieName { get; set; } = "haley.csrf";

    public string AntiforgeryHeaderName { get; set; } = "X-Haley-CSRF";

    public string AuthenticationScheme { get; set; } = "Bearer";

    public bool RequireHttps { get; set; } = true;
}
