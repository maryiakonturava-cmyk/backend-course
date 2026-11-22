using Microsoft.Extensions.Logging;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

internal static class RegistrationAudit
{
    public static void RegistrationAttempt(ILogger logger, string email, string outcome) =>
        logger.LogInformation("Registration audit EventName={EventName} Email={Email} Outcome={Outcome}",
            nameof(RegistrationAttempt), email, outcome);

    public static void RegistrationCodeSent(ILogger logger, string email, string outcome) =>
        logger.LogInformation("Registration audit EventName={EventName} Email={Email} Outcome={Outcome}",
            nameof(RegistrationCodeSent), email, outcome);

    public static void RegistrationConfirm(ILogger logger, string? email, string outcome) =>
        logger.LogInformation("Registration audit EventName={EventName} Email={Email} Outcome={Outcome}",
            nameof(RegistrationConfirm), email, outcome);
}
