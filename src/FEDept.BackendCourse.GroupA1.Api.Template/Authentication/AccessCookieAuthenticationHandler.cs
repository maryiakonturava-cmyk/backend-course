using System.Security.Claims;
using System.Text.Encodings.Web;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class AccessCookieAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    JwtTokenService tokens,
    AppDbContext db,
    AuthAudit audit) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "AccessCookie";

    private string _failure = "missing";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Only [Authorize] endpoints need the DB-backed check; anonymous ones must keep working during DB outages.
        var endpoint = Context.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<IAuthorizeData>() is null
            || endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            return AuthenticateResult.NoResult();
        }

        var token = Request.Cookies[AuthCookies.AccessCookie];
        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.NoResult();
        }

        var validation = await tokens.ValidateAsync(token, TokenUse.Access);
        if (validation is TokenValidation.Fail fail)
        {
            _failure = fail.Category;
            return AuthenticateResult.Fail(fail.Category);
        }

        var userId = ((TokenValidation.Ok)validation).UserId;
        var user = await db.Users.AsNoTracking()
            .Where(item => item.Id == userId)
            .Select(item => new { item.Id, item.Status })
            .SingleOrDefaultAsync(Context.RequestAborted);
        if (user is not { Status: UserStatus.Active })
        {
            _failure = "user_inactive";
            return AuthenticateResult.Fail(_failure);
        }

        // identity only; RBAC reads current roles from server data
        var identity = new ClaimsIdentity([new Claim("sub", userId.ToString())], SchemeName);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        audit.AccessRejected(_failure);
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        await Response.WriteAsJsonAsync(ErrorResponses.InvalidSession);
    }
}
