namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record LoginChallengeResponse(
    bool ConfirmationRequired,
    string Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds);

// 503 after the attempt was committed but SMTP refused the email; never carries the secret
public sealed record LoginChallengeFailedResponse(
    bool ConfirmationRequired,
    string Method,
    Guid AttemptId,
    int RetryAfterSeconds);

public sealed record LoginResendResponse(
    string Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds);
