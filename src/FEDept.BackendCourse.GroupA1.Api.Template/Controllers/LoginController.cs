using System.Globalization;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Controllers;

[ApiController]
[Route("auth")]
public sealed class LoginController(LoginService loginService, AuthCookies cookies, AuthAudit audit) : ControllerBase
{
    [HttpPost("login")]
    [EnableRateLimiting("login")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(RetryAfterResponse), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var result = await loginService.LoginAsync(request.Email, request.Password, clientIp, ct);

        return result switch
        {
            LoginResult.SignedIn signedIn => SignedIn(signedIn.Tokens),
            LoginResult.InvalidCredentials => Unauthorized(ErrorResponses.InvalidCredentials),
            LoginResult.TooManyRequests tooMany => TooManyRequests(tooMany.RetryAfterSeconds),
            _ => throw new InvalidOperationException("Unknown login result.")
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
