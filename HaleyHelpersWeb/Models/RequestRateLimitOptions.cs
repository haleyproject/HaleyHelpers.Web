namespace Haley.Models;

/// <summary>One fixed-window request allowance. A request consumes one permit, including successful reads.</summary>
public sealed class RequestRateLimitOptions
{
    public const int DefaultPermitLimit = 120;
    public const int DefaultWindowSeconds = 60;
    public const string IpScope = "ip";
    public const string IpUserScope = "ip-user";
    public bool Enabled { get; set; } = true;
    public int PermitLimit { get; set; } = DefaultPermitLimit;
    public int WindowSeconds { get; set; } = DefaultWindowSeconds;
    /// <summary>ip shares an allowance per address; ip-user separates subjects at that address.</summary>
    public string Scope { get; set; } = IpUserScope;

    public bool IsValid() => PermitLimit is >= 1 and <= 1_000_000 &&
        WindowSeconds is >= 1 and <= 86_400 &&
        (string.Equals(Scope, IpScope, StringComparison.OrdinalIgnoreCase) ||
         string.Equals(Scope, IpUserScope, StringComparison.OrdinalIgnoreCase));
}
