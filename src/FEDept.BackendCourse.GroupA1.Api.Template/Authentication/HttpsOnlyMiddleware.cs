using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

// rejects instead of redirecting, so a password sent over HTTP is not sent a second time
public sealed class HttpsOnlyMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.IsHttps && context.Request.Path.StartsWithSegments("/auth"))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(ErrorResponses.HttpsRequired);
            return;
        }

        await next(context);
    }
}
