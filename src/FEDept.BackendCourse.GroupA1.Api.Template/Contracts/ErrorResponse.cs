namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record ErrorResponse(string Code, string Message);

public sealed record RetryAfterResponse(string Code, string Message, int RetryAfterSeconds);

public static class ErrorResponses
{
    public static readonly ErrorResponse InvalidCredentials = new("invalid_credentials", "Email or password is incorrect.");
    public static readonly ErrorResponse InvalidSession = new("invalid_session", "The session is missing or no longer valid.");
    public static readonly ErrorResponse InvalidChallenge = new("invalid_challenge", "The code or link is invalid or expired.");
    public static readonly ErrorResponse AttemptsExhausted = new("too_many_requests", "Too many incorrect codes. Sign in again.");
    public static readonly ErrorResponse CsrfRejected = new("csrf_rejected", "The request origin is not allowed.");
    public static readonly ErrorResponse HttpsRequired = new("https_required", "Use HTTPS.");
    public static readonly ErrorResponse ServiceUnavailable = new("service_unavailable", "The service is temporarily unavailable. Try again later.");

    public static RetryAfterResponse TooManyRequests(int retryAfterSeconds) =>
        new("too_many_requests", "Too many requests. Try again later.", retryAfterSeconds);
}
