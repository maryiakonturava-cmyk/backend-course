using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class SecretHasherTests
{
    [Fact]
    public void Hash_IsStableAndMatchesSameCodeAndKey()
    {
        var hasher = new SecretHasher("test-key");

        var firstHash = hasher.Hash("004219");
        var secondHash = hasher.Hash("004219");

        Assert.Equal(firstHash, secondHash);
        Assert.True(hasher.Matches("004219", firstHash));
    }

    [Fact]
    public void Matches_ReturnsFalseForDifferentCode()
    {
        var hasher = new SecretHasher("test-key");

        Assert.False(hasher.Matches("004220", hasher.Hash("004219")));
    }

    [Fact]
    public void Hash_DoesNotExposeCode()
    {
        var hasher = new SecretHasher("test-key");

        Assert.NotEqual("004219", hasher.Hash("004219"));
    }
}
