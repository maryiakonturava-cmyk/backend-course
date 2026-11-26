using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class DependencyFailureHandler(AuthAudit audit) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var dependency = exception is TokenSigningException ? "signing" : IsDatabaseUnavailable(exception) ? "db" : null;
        if (dependency is null)
        {
            return false;
        }

        audit.DependencyUnavailable(dependency);
        httpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await httpContext.Response.WriteAsJsonAsync(ErrorResponses.ServiceUnavailable, cancellationToken);
        return true;
    }

    // a constraint violation is a bug (500); only connection-level or transient errors are an outage
    private static bool IsDatabaseUnavailable(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is NpgsqlException npgsql)
            {
                return npgsql is not PostgresException || npgsql.IsTransient;
            }
        }

        return false;
    }
}
