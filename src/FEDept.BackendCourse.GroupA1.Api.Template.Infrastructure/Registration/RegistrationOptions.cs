namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class RegistrationOptions
{
    public bool ConfirmationEnabled { get; set; }

    public string HmacKey { get; set; } = string.Empty;

    public int RateLimitPermitPerWindow { get; set; }
}
