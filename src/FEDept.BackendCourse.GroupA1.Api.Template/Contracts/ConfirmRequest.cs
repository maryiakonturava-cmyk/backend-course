using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record ConfirmRequest(Guid? AttemptId, string? Code, string? Token = null) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var isOtp = AttemptId is not null && !string.IsNullOrWhiteSpace(Code) && Token is null;
        // 32 random bytes in base64url are always 43 chars
        var isLink = AttemptId is null && Code is null && Token is { Length: 43 };
        if (!isOtp && !isLink)
        {
            yield return new ValidationResult(
                "Provide either attemptId and code, or token.",
                [nameof(AttemptId), nameof(Code), nameof(Token)]);
        }
    }
}
