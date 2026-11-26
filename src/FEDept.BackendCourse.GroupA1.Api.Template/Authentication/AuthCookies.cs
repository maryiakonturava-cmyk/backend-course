using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class AuthCookies(IOptions<FrontendOptions> frontend)
{
    public const string AccessCookie = "access_token";
    public const string RefreshCookie = "refresh_token";
    public const string RefreshPath = "/auth/refresh";

    public void Set(HttpResponse response, TokenPair tokens)
    {
        response.Cookies.Append(AccessCookie, tokens.AccessToken, Options("/", JwtTokenService.AccessLifetime));
        response.Cookies.Append(RefreshCookie, tokens.RefreshToken, Options(RefreshPath, JwtTokenService.RefreshLifetime));
    }

    // same name, Path, Secure and SameSite as when set, so the browser replaces the cookie
    public void Clear(HttpResponse response)
    {
        response.Cookies.Append(AccessCookie, string.Empty, Options("/", TimeSpan.Zero));
        response.Cookies.Append(RefreshCookie, string.Empty, Options(RefreshPath, TimeSpan.Zero));
    }

    private CookieOptions Options(string path, TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = frontend.Value.CrossSite ? SameSiteMode.None : SameSiteMode.Strict,
        Path = path,
        MaxAge = maxAge
    };
}
