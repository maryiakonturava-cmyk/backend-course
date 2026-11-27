using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record LoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;

    // kept exactly as sent: no trimming or normalization
    [Required]
    public string Password { get; init; } = string.Empty;
}
