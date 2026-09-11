using System.Globalization;

namespace Haley.Utils;

public static class HttpRequestValueExtensions
{
    public static bool TryTakeSingleHeaderValue(
        this HttpRequest request,
        string headerName,
        out string? value)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerName);

        var values = request.Headers[headerName];
        request.Headers.Remove(headerName);
        if (values.Count == 0)
        {
            value = null;
            return true;
        }

        if (values.Count == 1 && !string.IsNullOrWhiteSpace(values[0]))
        {
            value = values[0]!.Trim();
            return true;
        }

        value = null;
        return false;
    }

    public static bool TryGetGuidRouteValue(
        this HttpRequest request,
        string name,
        out Guid value)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var raw = Convert.ToString(
            request.RouteValues.GetValueOrDefault(name),
            CultureInfo.InvariantCulture);
        return Guid.TryParse(raw, out value);
    }
}
