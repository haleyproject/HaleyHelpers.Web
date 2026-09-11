using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Constants;
using Haley.Internal;
using Haley.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Haley.Middleware;

internal sealed class BrowserSessionBoundaryMiddleware(
    RequestDelegate next,
    IOptions<BrowserSessionBoundaryOptions> options)
{
    private readonly BrowserSessionBoundaryOptions _options = options.Value;

    public async Task InvokeAsync(HttpContext context, IBrowserSessionManager browserSessions)
    {
        var hasExplicitAuthorization = !string.IsNullOrWhiteSpace(context.Request.Headers.Authorization);
        var hasSessionCookie = context.Request.Cookies.ContainsKey(_options.AccessCookieName) ||
                               context.Request.Cookies.ContainsKey(_options.RefreshCookieName);
        if (hasSessionCookie && IsUnsafe(context.Request.Method) && !ValidAntiforgery(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(
                new ProblemDetails
                {
                    Status = StatusCodes.Status403Forbidden,
                    Title = $"A matching {_options.AntiforgeryHeaderName} header is required.",
                    Extensions =
                    {
                        ["code"] = BrowserSessionErrorCodes.AntiforgeryRejected
                    }
                },
                context.RequestAborted).ConfigureAwait(false);
            return;
        }

        if (!hasExplicitAuthorization &&
            context.Request.Cookies.TryGetValue(_options.AccessCookieName, out var ticket) &&
            browserSessions.TryUnprotectAccess(ticket, out var access) &&
            access is not null)
        {
            try
            {
                var payload = JsonSerializer.Deserialize<BrowserAccessPayload>(access.Payload);
                if (payload is not null && !string.IsNullOrWhiteSpace(payload.AccessToken))
                {
                    context.Request.Headers.Authorization = $"{_options.AuthenticationScheme} {payload.AccessToken}";
                    context.Items[BrowserSessionContextItemKeys.CookieAuthentication] = true;
                    if (payload.TenantId is not null && payload.TenantId != Guid.Empty)
                        context.Items[BrowserSessionContextItemKeys.TenantId] = payload.TenantId.Value;
                }
            }
            catch (JsonException)
            {
                // Authentication remains absent when an access envelope has an invalid payload.
            }
            finally
            {
                CryptographicOperations.ZeroMemory(access.Payload);
            }
        }

        await next(context).ConfigureAwait(false);
    }

    private static bool IsUnsafe(string method) =>
        !HttpMethods.IsGet(method) &&
        !HttpMethods.IsHead(method) &&
        !HttpMethods.IsOptions(method) &&
        !HttpMethods.IsTrace(method);

    private bool ValidAntiforgery(HttpRequest request)
    {
        var cookie = request.Cookies[_options.AntiforgeryCookieName];
        var header = request.Headers[_options.AntiforgeryHeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(cookie) || string.IsNullOrWhiteSpace(header)) return false;
        var first = Encoding.UTF8.GetBytes(cookie);
        var second = Encoding.UTF8.GetBytes(header);
        return first.Length == second.Length && CryptographicOperations.FixedTimeEquals(first, second);
    }
}
