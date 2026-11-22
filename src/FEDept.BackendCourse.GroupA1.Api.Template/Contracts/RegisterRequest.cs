using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record RegisterRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;

    [Required]
    [PasswordPolicy]
    public string Password { get; init; } = string.Empty;

    public RegisterRequest()
    {
    }

    public RegisterRequest(string email, string password)
    {
        Email = email;
        Password = password;
    }
}
