using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

// browsers always send Origin on cross-origin POST; no Origin means a non-browser client
public sealed class CsrfMiddleware(RequestDelegate next, IOptions<FrontendOptions> frontend, AuthAudit audit)
{
    public const string HeaderName = "X-CSRF-Protection";

    public async Task InvokeAsync(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method)
            && !HttpMethods.IsHead(context.Request.Method)
            && !HttpMethods.IsOptions(context.Request.Method)
            && !HttpMethods.IsTrace(context.Request.Method)
            && Rejection(context.Request) is { } reason)
        {
            audit.CsrfRejected(reason);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(ErrorResponses.CsrfRejected);
            return;
        }

        await next(context);
    }

    private string? Rejection(HttpRequest request)
    {
        var origin = request.Headers.Origin.ToString();
        if (origin.Length == 0 || string.Equals(origin, $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.Equals(origin, frontend.Value.Origin, StringComparison.Ordinal))
        {
            return "origin";
        }

        return request.Headers[HeaderName] == "1" ? null : "header";
    }
}
