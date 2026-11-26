using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class MagicLinkTokenGeneratorTests
{
    [Fact]
    public void Generate_Returns43Base64UrlCharsAndDistinctValues()
    {
        var tokens = Enumerable.Range(0, 100).Select(_ => MagicLinkTokenGenerator.Generate()).ToList();

        Assert.All(tokens, token => Assert.Matches("^[A-Za-z0-9_-]{43}$", token));
        Assert.Equal(tokens.Count, tokens.Distinct().Count());
    }
}
