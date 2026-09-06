using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

namespace Haley.Models;

public sealed class UnsafeMethodAntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        if (!HttpMethods.IsGet(context.HttpContext.Request.Method) &&
            !HttpMethods.IsHead(context.HttpContext.Request.Method) &&
            !HttpMethods.IsOptions(context.HttpContext.Request.Method))
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext).ConfigureAwait(false);
        }

        return await next(context).ConfigureAwait(false);
    }
}
