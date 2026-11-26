using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class AuthConfigurationTests
{
    private static readonly string KeyA = new('a', 32);
    private static readonly string KeyB = new('b', 32);
    private static readonly string KeyC = new('c', 32);
    private static readonly string KeyD = new('d', 32);

    private static JwtOptions Jwt(string access, string refresh) =>
        new() { AccessSecret = access, RefreshSecret = refresh, Issuer = "api", Audience = "web" };

    private static LoginOptions Login(string challenge, string audit) =>
        new() { ChallengeHmacKey = challenge, AuditHmacKey = audit };

    [Fact]
    public void Errors_ValidSettings_ReturnsNone()
    {
        var errors = AuthConfigurationValidator.Errors(Jwt(KeyA, KeyB), Login(KeyC, KeyD), new FrontendOptions(), isDevelopment: false);

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData(16, true)]
    [InlineData(15, false)]
    public void Errors_KeyLength_UsesUtf8Bytes(int characterCount, bool valid)
    {
        var secret = new string('é', characterCount);
        var errors = AuthConfigurationValidator.Errors(Jwt(secret, KeyB), Login(KeyC, KeyD), new FrontendOptions(), false);

        Assert.Equal(!valid, errors.Any(error => error.Contains("Jwt:AccessSecret", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("short-key")]
    [InlineData("0123456789012345678901234567890")]
    public void Errors_ShortAccessSecret_IsReported(string access)
    {
        var errors = AuthConfigurationValidator.Errors(Jwt(access, KeyB), Login(KeyC, KeyD), new FrontendOptions(), false);

        Assert.Contains(errors, error => error.Contains("Jwt:AccessSecret", StringComparison.Ordinal));
    }

    [Fact]
    public void Errors_MultipleShortKeys_DoesNotReportSharedKeys()
    {
        var errors = AuthConfigurationValidator.Errors(Jwt("", ""), Login("", ""), new FrontendOptions(), false);

        Assert.DoesNotContain(errors, error => error.Contains("must all differ", StringComparison.Ordinal));
    }

    [Fact]
    public void Errors_SharedKey_IsReported()
    {
        var errors = AuthConfigurationValidator.Errors(Jwt(KeyA, KeyA), Login(KeyC, KeyD), new FrontendOptions(), false);

        Assert.Contains(errors, error => error.Contains("must all differ", StringComparison.Ordinal));
    }

    [Fact]
    public void Errors_MissingIssuerAndAudience_AreReported()
    {
        var jwt = Jwt(KeyA, KeyB);
        jwt.Issuer = "";
        jwt.Audience = " ";

        var errors = AuthConfigurationValidator.Errors(jwt, Login(KeyC, KeyD), new FrontendOptions(), false).ToList();

        Assert.Contains(errors, error => error.Contains("Jwt:Issuer", StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains("Jwt:Audience", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0, 30, "Login:LoginPermitPerMinute")]
    [InlineData(-1, 30, "Login:LoginPermitPerMinute")]
    [InlineData(30, 0, "Login:RefreshPermitPerMinute")]
    [InlineData(30, -1, "Login:RefreshPermitPerMinute")]
    public void Errors_NonPositivePermit_IsReported(int loginPermit, int refreshPermit, string expectedError)
    {
        var login = Login(KeyC, KeyD);
        login.LoginPermitPerMinute = loginPermit;
        login.RefreshPermitPerMinute = refreshPermit;

        var errors = AuthConfigurationValidator.Errors(Jwt(KeyA, KeyB), login, new FrontendOptions(), false);

        Assert.Contains(errors, error => error.Contains(expectedError, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("", false, false)]
    [InlineData("/login/confirm", false, false)]
    [InlineData("http://localhost:3000/login/confirm", false, false)]
    [InlineData("https://app.example.com/login/confirm#x", false, false)]
    [InlineData("http://localhost:3000/login/confirm", true, true)]
    [InlineData("https://app.example.com/login/confirm", false, true)]
    public void Errors_MagicLinkBaseUrl_RequiresAbsoluteHttpsUrl(string url, bool isDevelopment, bool valid)
    {
        var login = Login(KeyC, KeyD);
        login.ConfirmationMethod = ChallengeMethod.MagicLink;
        login.MagicLinkBaseUrl = url;

        var errors = AuthConfigurationValidator.Errors(Jwt(KeyA, KeyB), login, new FrontendOptions(), isDevelopment);

        Assert.Equal(!valid, errors.Any(error => error.Contains("Login:MagicLinkBaseUrl", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("https://app.example.com", true)]
    [InlineData("http://localhost:3000", true)]
    [InlineData("https://app.example.com/", false)]
    [InlineData("https://app.example.com/path", false)]
    [InlineData("app.example.com", false)]
    public void Errors_FrontendOrigin_MustBeExactOrigin(string origin, bool valid)
    {
        var errors = AuthConfigurationValidator.Errors(Jwt(KeyA, KeyB), Login(KeyC, KeyD), new FrontendOptions { Origin = origin }, false);

        Assert.Equal(!valid, errors.Any(error => error.Contains("Frontend:Origin", StringComparison.Ordinal)));
    }
}

public sealed class AuthConfigurationStartupTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    [Fact]
    public void Startup_WithShortKey_Fails()
    {
        using var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Jwt:RefreshSecret"] = "too-short"
                })));

        var exception = Record.Exception(() => app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        }));

        Assert.NotNull(exception);
        Assert.Contains("Jwt:RefreshSecret", exception.ToString(), StringComparison.Ordinal);
    }
}
