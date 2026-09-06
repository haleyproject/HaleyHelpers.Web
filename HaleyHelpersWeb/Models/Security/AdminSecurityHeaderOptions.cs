using Microsoft.AspNetCore.Http;

namespace Haley.Models;

public sealed class AdminSecurityHeaderOptions
{
    public string ContentSecurityPolicy { get; set; } =
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; " +
        "script-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; " +
        "frame-ancestors 'none'; form-action 'self'";

    public PathString ApiPathPrefix { get; set; } = new("/admin/api");
}
