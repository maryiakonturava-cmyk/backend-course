using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// never pass emails, secrets, tokens, cookies or bodies here; RequestId comes from the logging scope
public sealed class AuthAudit(ILogger<AuthAudit> logger, IOptions<LoginOptions> options)
{
    public string EmailRef(string normalizedEmail)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(options.Value.AuditHmacKey));
        return Base64Url.EncodeToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(normalizedEmail)));
    }

    public void Login(Guid? userId, string? emailRef, string outcome) =>
        logger.LogInformation("Auth audit EventName={EventName} UserId={UserId} EmailRef={EmailRef} Outcome={Outcome}",
            "Login", userId, userId is null ? emailRef : null, outcome);

    public void Challenge(Guid? userId, Guid attemptId, ChallengeMethod? method, string outcome) =>
        logger.LogInformation("Auth audit EventName={EventName} UserId={UserId} AttemptId={AttemptId} Method={Method} Outcome={Outcome}",
            "LoginChallenge", userId, attemptId, method?.ToContractName(), outcome);

    public void Refresh(Guid? userId, string outcome, string? category) =>
        logger.LogInformation("Auth audit EventName={EventName} UserId={UserId} Outcome={Outcome} Category={Category}",
            "Refresh", userId, outcome, category);

    public void Logout() =>
        logger.LogInformation("Auth audit EventName={EventName} Outcome={Outcome}", "Logout", "success");

    public void AccessRejected(string category) =>
        logger.LogInformation("Auth audit EventName={EventName} Outcome={Outcome} Category={Category}",
            "AccessRejected", "failure", category);

    public void DependencyUnavailable(string dependency) =>
        logger.LogWarning("Auth audit EventName={EventName} Outcome={Outcome} Category={Category}",
            "DependencyUnavailable", "failure", dependency);

    public void CsrfRejected(string reason) =>
        logger.LogWarning("Auth audit EventName={EventName} Outcome={Outcome} Category={Category}",
            "CsrfRejected", "failure", reason);
}
