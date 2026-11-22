namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record ConfirmationRequiredResponse(
    bool ConfirmationRequired,
    string Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds);
