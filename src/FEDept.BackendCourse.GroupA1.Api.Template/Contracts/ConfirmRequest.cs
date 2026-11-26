using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record ConfirmRequest(Guid? AttemptId, string? Code, string? Token = null) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var isOtp = AttemptId is not null && !string.IsNullOrEmpty(Code) && Token is null;
        var isLink = AttemptId is null && Code is null && !string.IsNullOrEmpty(Token);
        if (!isOtp && !isLink)
        {
            yield return new ValidationResult(
                "Provide either attemptId and code, or token.",
                [nameof(AttemptId), nameof(Code), nameof(Token)]);
        }
    }
}
