using System.ComponentModel.DataAnnotations;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class RegisterValidationTests
{
    [Theory]
    [InlineData("abc12")]
    [InlineData("abcdefgh")]
    [InlineData("12345678")]
    public void Validate_InvalidPassword_ReturnsValidationError(string password)
    {
        var errors = Validate(new RegisterRequest("user@example.com", password));

        Assert.Contains(errors, error => error.MemberNames.Contains(nameof(RegisterRequest.Password)));
    }

    [Theory]
    [InlineData(72, true)]
    [InlineData(73, false)]
    public void Validate_UsesUtf8ByteLengthForPasswordLimit(int byteCount, bool isValid)
    {
        var multibyteCharacters = new string('é', 35);
        var password = multibyteCharacters + (byteCount == 72 ? "a1" : "a12");
        var errors = Validate(new RegisterRequest("user@example.com", password));

        Assert.Equal(isValid, !errors.Any(error => error.MemberNames.Contains(nameof(RegisterRequest.Password))));
    }

    [Theory]
    [InlineData("abcd1234")]
    [InlineData(" abcd1234 ")]
    public void Validate_PasswordWithLetterAndDigitAndAtLeastEightCharacters_IsValid(string password)
    {
        var errors = Validate(new RegisterRequest("user@example.com", password));

        Assert.DoesNotContain(errors, error => error.MemberNames.Contains(nameof(RegisterRequest.Password)));
    }

    [Theory]
    [InlineData("", "abcd1234")]
    [InlineData("not-an-email", "abcd1234")]
    [InlineData("user@example.com", "")]
    public void Validate_RequiredAndEmailRules_AreApplied(string email, string password)
    {
        var errors = Validate(new RegisterRequest(email, password));

        Assert.NotEmpty(errors);
    }

    private static List<ValidationResult> Validate(RegisterRequest request)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(request, new ValidationContext(request), results, validateAllProperties: true);
        return results;
    }
}
