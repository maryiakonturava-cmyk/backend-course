using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class LoginOptions
{
    public bool ConfirmationEnabled { get; set; }

    public ChallengeMethod ConfirmationMethod { get; set; } = ChallengeMethod.Otp;

    public string ChallengeHmacKey { get; set; } = string.Empty;

    public string AuditHmacKey { get; set; } = string.Empty;

    public string MagicLinkBaseUrl { get; set; } = string.Empty;

    public int LoginPermitPerMinute { get; set; } = 30;

    public int RefreshPermitPerMinute { get; set; } = 30;
}
