using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record RegisterRequest(
    [property: Required]
    [property: EmailAddress]
    string Email,
    [property: Required]
    [property: PasswordPolicy]
    string Password);
