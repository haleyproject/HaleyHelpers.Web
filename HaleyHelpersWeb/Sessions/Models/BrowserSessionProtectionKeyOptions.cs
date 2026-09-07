namespace Haley.Models;

public sealed class BrowserSessionProtectionKeyOptions
{
    public string KeyId { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public string Status { get; set; } = "retiring";
}
