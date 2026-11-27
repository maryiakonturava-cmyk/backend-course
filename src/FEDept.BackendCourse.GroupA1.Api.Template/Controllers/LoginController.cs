using System.Globalization;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Controllers;

[ApiController]
[Route("auth")]
public sealed class LoginController(LoginService loginService, AuthCookies cookies, AuthAudit audit) : ControllerBase
{
    private const int ExpiresInSeconds = 600;
    private const int ResendAfterSeconds = 60;

    [HttpPost("login")]
    [EnableRateLimiting("login")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(LoginChallengeResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(RetryAfterResponse), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(LoginChallengeFailedResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var result = await loginService.LoginAsync(request.Email, request.Password, clientIp, ct);

        return result switch
        {
            LoginResult.SignedIn signedIn => SignedIn(signedIn.Tokens),
            LoginResult.ChallengeSent sent => Accepted(new LoginChallengeResponse(
                true, sent.Method.ToContractName(), sent.AttemptId, ExpiresInSeconds, ResendAfterSeconds)),
            LoginResult.ChallengeNotSent notSent => StatusCode(StatusCodes.Status503ServiceUnavailable,
                new LoginChallengeFailedResponse(true, notSent.Method.ToContractName(), notSent.AttemptId, notSent.RetryAfterSeconds)),
            LoginResult.InvalidCredentials => Unauthorized(ErrorResponses.InvalidCredentials),
            LoginResult.TooManyRequests tooMany => TooManyRequests(tooMany.RetryAfterSeconds),
            _ => throw new InvalidOperationException("Unknown login result.")
        };
    }

    [HttpPost("login/confirm")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Confirm(LoginConfirmRequest request, CancellationToken ct)
    {
        // model validation already rejected every shape TryParse refuses
        request.TryParse(out var attemptId, out var method, out var secret);
        var result = await loginService.ConfirmAsync(attemptId, method, secret, ct);

        return result switch
        {
            LoginConfirmResult.SignedIn signedIn => SignedIn(signedIn.Tokens),
            LoginConfirmResult.Invalid => BadRequest(ErrorResponses.InvalidChallenge),
            LoginConfirmResult.Exhausted => StatusCode(StatusCodes.Status429TooManyRequests, ErrorResponses.AttemptsExhausted),
            LoginConfirmResult.InvalidCredentials => Unauthorized(ErrorResponses.InvalidCredentials),
            _ => throw new InvalidOperationException("Unknown confirmation result.")
        };
    }

    [HttpPost("login/resend")]
    [ProducesResponseType(typeof(LoginResendResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(RetryAfterResponse), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Resend(LoginResendRequest request, CancellationToken ct)
    {
        var result = await loginService.ResendAsync(request.AttemptId!.Value, ct);

        return result switch
        {
            LoginResendResult.Sent sent => Accepted(new LoginResendResponse(
                sent.Method.ToContractName(), sent.AttemptId, ExpiresInSeconds, ResendAfterSeconds)),
            LoginResendResult.NotSent => StatusCode(StatusCodes.Status503ServiceUnavailable, ErrorResponses.ServiceUnavailable),
            LoginResendResult.TooSoon tooSoon => TooManyRequests(tooSoon.RetryAfterSeconds),
            LoginResendResult.Invalid => BadRequest(ErrorResponses.InvalidChallenge),
            LoginResendResult.Exhausted => StatusCode(StatusCodes.Status429TooManyRequests, ErrorResponses.AttemptsExhausted),
            LoginResendResult.InvalidCredentials => Unauthorized(ErrorResponses.InvalidCredentials),
            _ => throw new InvalidOperationException("Unknown resend result.")
        };
    }

    [HttpPost("refresh")]
    [EnableRateLimiting("refresh")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(RetryAfterResponse), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        var tokens = await loginService.RefreshAsync(Request.Cookies[AuthCookies.RefreshCookie], ct);
        return tokens is null ? Unauthorized(ErrorResponses.InvalidSession) : SignedIn(tokens);
    }

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    public IActionResult Logout()
    {
        cookies.Clear(Response);
        audit.Logout();
        return NoContent();
    }

    private NoContentResult SignedIn(TokenPair tokens)
    {
        cookies.Set(Response, tokens);
        return NoContent();
    }

    private ObjectResult TooManyRequests(int retryAfterSeconds)
    {
        Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        return StatusCode(StatusCodes.Status429TooManyRequests, ErrorResponses.TooManyRequests(retryAfterSeconds));
    }
}
