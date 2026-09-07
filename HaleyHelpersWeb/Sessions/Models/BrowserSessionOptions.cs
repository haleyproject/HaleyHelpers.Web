namespace Haley.Models;

public sealed class BrowserSessionOptions
{
    public const string DefaultSectionName = "Haley:BrowserSessions";

    public string Adapter { get; set; } = string.Empty;

    public string Scope { get; set; } = string.Empty;

    public bool Initialize { get; set; } = true;

    public int HandleBytes { get; set; } = 32;

    public int LeaseSeconds { get; set; } = 30;

    public int CleanupSeconds { get; set; } = 300;

    public int RetentionSeconds { get; set; } = 86400;

    public int MaximumAccessPayloadBytes { get; set; } = 2800;

    public int MaximumRefreshPayloadBytes { get; set; } = 4096;

    public BrowserSessionProtectionOptions Protection { get; set; } = new();
}
