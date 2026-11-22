using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.Mvc;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Controllers;

[ApiController]
[Route("auth")]
public sealed class RegistrationController(RegistrationService registrationService) : ControllerBase
{
    [HttpPost("register")]
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
                new ConfirmationRequiredResponse(true, "otp", confirmation.AttemptId, 600, 60)),
            RegisterResult.Conflict => Conflict(),
            _ => throw new InvalidOperationException("Unknown registration result.")
        };
    }

    [HttpPost("register/resend")]
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
                new ConfirmationRequiredResponse(true, "otp", sent.AttemptId, 600, 60)),
            ResendResult.TooSoon => StatusCode(StatusCodes.Status429TooManyRequests),
            ResendResult.NotFound => NotFound(),
            _ => throw new InvalidOperationException("Unknown resend result.")
        };
    }

    [HttpPost("register/confirm")]
    public async Task<IActionResult> Confirm(ConfirmRequest request, CancellationToken ct)
    {
        var result = await registrationService.ConfirmAsync(request.AttemptId, request.Code, ct);

        return result switch
        {
            ConfirmResult.Success success => Ok(new ConfirmedResponse(success.User.Id, success.User.Email, "active")),
            ConfirmResult.Invalid => BadRequest(),
            ConfirmResult.Exhausted => StatusCode(StatusCodes.Status429TooManyRequests),
            _ => throw new InvalidOperationException("Unknown confirmation result.")
        };
    }
}
