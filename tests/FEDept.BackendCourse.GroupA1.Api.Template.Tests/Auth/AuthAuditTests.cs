using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class AuthAuditTests
{
    [Fact]
    public void EmailRef_IsDeterministicKeyedAndDoesNotContainEmail()
    {
        const string email = "member@example.com";
        var audit = Create(new string('k', 32));
        var otherKeyAudit = Create(new string('x', 32));

        var first = audit.EmailRef(email);
        var second = audit.EmailRef(email);
        var otherKey = otherKeyAudit.EmailRef(email);

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherKey);
        Assert.DoesNotContain(email, first);
    }

    private static AuthAudit Create(string key) => new(
        NullLogger<AuthAudit>.Instance,
        Options.Create(new LoginOptions { AuditHmacKey = key }));
}
