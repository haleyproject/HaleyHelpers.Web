namespace Haley.Models;

public sealed class BrowserSessionProtectionOptions
{
    public string ActiveKeyId { get; set; } = string.Empty;

    public List<BrowserSessionProtectionKeyOptions> Keys { get; set; } = [];
}
