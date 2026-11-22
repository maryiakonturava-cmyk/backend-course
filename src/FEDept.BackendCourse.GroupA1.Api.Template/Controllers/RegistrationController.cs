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
        var result = await registrationService.RegisterAsync(request.Email, request.Password, ct);

        return result switch
        {
            RegisterResult.Active active => StatusCode(StatusCodes.Status201Created,
                new RegisterActiveResponse(active.Id, active.Email, "active")),
            RegisterResult.ConfirmationRequired confirmation => Accepted(
                new ConfirmationRequiredResponse(true, "otp", confirmation.AttemptId, 600, 60)),
            _ => throw new InvalidOperationException("Unknown registration result.")
        };
    }
}
