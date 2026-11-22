using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class OtpGeneratorTests
{
    [Fact]
    public void Generate_ReturnsExactlySixAsciiDigits()
    {
        var otps = Enumerable.Range(0, 100).Select(_ => OtpGenerator.Generate());

        Assert.All(otps, otp => Assert.Matches("^[0-9]{6}$", otp));
    }
}
