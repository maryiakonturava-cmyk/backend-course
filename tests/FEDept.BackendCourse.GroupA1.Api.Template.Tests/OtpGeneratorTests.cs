using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class OtpGeneratorTests
{
    [Fact]
    public void Generate_ReturnsExactlySixAsciiDigits()
    {
        var otp = OtpGenerator.Generate();

        Assert.Matches("^[0-9]{6}$", otp);
    }
}
