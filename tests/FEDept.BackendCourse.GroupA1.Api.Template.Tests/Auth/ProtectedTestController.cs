using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

[ApiController]
[Authorize]
[Route("test/protected")]
public sealed class ProtectedTestController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new { userId = User.FindFirst("sub")?.Value });
}
