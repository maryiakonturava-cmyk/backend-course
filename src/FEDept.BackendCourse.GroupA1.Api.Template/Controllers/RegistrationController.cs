using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Controllers;

[ApiController]
[Route("auth")]
public sealed class RegistrationController(RegistrationService registrationService) : ControllerBase
{
    [HttpPost("register")]
    [ProducesResponseType(typeof(RegisterActiveResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ConfirmationRequiredResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        RegisterResult result;
        try
        {
            result = await registrationService.RegisterAsync(request.Email, request.Password, ct);
        }
        catch (EmailDeliveryException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        return result switch
        {
            RegisterResult.Active active => StatusCode(StatusCodes.Status201Created,
                new RegisterActiveResponse(active.Id, active.Email, "active")),
            RegisterResult.ConfirmationRequired confirmation => Accepted(
                new ConfirmationRequiredResponse(true, confirmation.Method.ToContractName(), confirmation.AttemptId, 600, 60)),
            RegisterResult.Conflict => Conflict(),
            _ => throw new InvalidOperationException("Unknown registration result.")
        };
    }

    [HttpPost("register/resend")]
    [ProducesResponseType(typeof(ConfirmationRequiredResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Resend(ResendRequest request, CancellationToken ct)
    {
        ResendResult result;
        try
        {
            result = await registrationService.ResendAsync(request.Email, ct);
        }
        catch (EmailDeliveryException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        return result switch
        {
            ResendResult.Sent sent => Accepted(
                new ConfirmationRequiredResponse(true, sent.Method.ToContractName(), sent.AttemptId, 600, 60)),
            ResendResult.TooSoon => StatusCode(StatusCodes.Status429TooManyRequests),
            ResendResult.NotFound => NotFound(),
            _ => throw new InvalidOperationException("Unknown resend result.")
        };
    }

    [HttpPost("register/confirm")]
    [EnableRateLimiting("registration")]
    [ProducesResponseType(typeof(ConfirmedResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Confirm(ConfirmRequest request, CancellationToken ct)
    {
        var result = request.Token is not null
            ? await registrationService.ConfirmTokenAsync(request.Token, ct)
            : await registrationService.ConfirmOtpAsync(request.AttemptId!.Value, request.Code!, ct);

        return result switch
        {
            ConfirmResult.Success success => Ok(new ConfirmedResponse(success.User.Id, success.User.Email, "active")),
            ConfirmResult.Invalid => BadRequest(),
            ConfirmResult.Exhausted => StatusCode(StatusCodes.Status429TooManyRequests),
            _ => throw new InvalidOperationException("Unknown confirmation result.")
        };
    }
}
