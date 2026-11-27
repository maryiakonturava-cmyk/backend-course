using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class DependencyFailureHandlerTests
{
    private readonly DependencyFailureHandler _handler = new(
        new AuthAudit(NullLogger<AuthAudit>.Instance, Options.Create(new LoginOptions { AuditHmacKey = new string('k', 32) })));

    public static TheoryData<Exception> DependencyFailures() => new()
    {
        new TokenSigningException(new InvalidOperationException()),
        new InvalidOperationException("wrapped signing", new TokenSigningException(new InvalidOperationException())),
        new NpgsqlException("connection refused"),
        new InvalidOperationException("wrapped", new NpgsqlException("connection refused")),
        new PostgresException("shutdown", "FATAL", "FATAL", PostgresErrorCodes.AdminShutdown)
    };

    [Theory]
    [MemberData(nameof(DependencyFailures))]
    public async Task DependencyFailure_Returns503ServiceUnavailable(Exception exception)
    {
        var context = new DefaultHttpContext { Response = { Body = new MemoryStream() } };

        var handled = await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(503, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal("service_unavailable", body.RootElement.GetProperty("code").GetString());
    }

    public static TheoryData<Exception> OtherExceptions() => new()
    {
        new InvalidOperationException(),
        new PostgresException("dup", "ERROR", "ERROR", PostgresErrorCodes.UniqueViolation),
        new DbUpdateException("x", new PostgresException("dup", "ERROR", "ERROR", PostgresErrorCodes.UniqueViolation))
    };

    [Theory]
    [MemberData(nameof(OtherExceptions))]
    public async Task OtherException_IsNotHandled(Exception exception)
    {
        var handled = await _handler.TryHandleAsync(new DefaultHttpContext(), exception, CancellationToken.None);

        Assert.False(handled);
    }
}
