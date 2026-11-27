using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed partial record LoginConfirmRequest(Guid? AttemptId, string? Code, string? Token) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!TryParse(out _, out _, out _))
        {
            yield return new ValidationResult(
                "Provide either attemptId and a 6-digit code, or token.",
                [nameof(AttemptId), nameof(Code), nameof(Token)]);
        }
    }

    // token is "{attemptId}.{secret}": a 36-char Guid and 32 random bytes in base64url (43 chars)
    public bool TryParse(out Guid attemptId, out ChallengeMethod method, out string secret)
    {
        if (AttemptId is { } id && Token is null && Code is not null && OtpCode().IsMatch(Code))
        {
            (attemptId, method, secret) = (id, ChallengeMethod.Otp, Code);
            return true;
        }

        if (AttemptId is null && Code is null && Token is not null && LinkToken().IsMatch(Token)
            && Guid.TryParseExact(Token[..36], "D", out var tokenId))
        {
            (attemptId, method, secret) = (tokenId, ChallengeMethod.MagicLink, Token[37..]);
            return true;
        }

        (attemptId, method, secret) = (Guid.Empty, ChallengeMethod.Otp, string.Empty);
        return false;
    }

    [GeneratedRegex(@"^[0-9]{6}\z")]
    private static partial Regex OtpCode();

    [GeneratedRegex(@"^[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{43}\z")]
    private static partial Regex LinkToken();
}
