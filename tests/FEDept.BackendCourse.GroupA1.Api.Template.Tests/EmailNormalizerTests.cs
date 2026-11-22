using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class EmailNormalizerTests
{
    [Fact]
    public void Normalize_TrimsAndLowercasesEmail()
    {
        Assert.Equal("user@example.com", EmailNormalizer.Normalize(" User@Example.com "));
    }
}
