# Login Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Email-and-password sign-in with JWT access/refresh in HttpOnly cookies, an optional OTP or magic-link email challenge, stateless refresh, logout, a shared access check, CSRF/CORS, rate limits and audit, as specified in `docs/superpowers/specs/2026-11-26-login-authentication-design.md`.

**Architecture:** Infrastructure gets an `Authentication/` folder (`JwtTokenService`, `LoginService`, `LoginChallenge`, `FailedLoginLimiter`, `AuthAudit`, options). The API gets `LoginController`, an `Authentication/` folder (cookie helper, `AccessCookie` authentication handler, CSRF and HTTPS middleware, exception handler, options validator) and new contracts. Registration code stays untouched except DI wiring.

**Tech Stack:** .NET 10, ASP.NET Core controllers, EF Core 10 + Npgsql, `Microsoft.IdentityModel.JsonWebTokens` 8.23.0, BCrypt.Net-Next, MailKit, xUnit + Testcontainers PostgreSQL.

---

## Deviations from the spec (decided while planning)

1. **`ILoginEmailSender` instead of new methods on `IEmailSender`.** Six test fakes implement `IEmailSender`; a separate interface keeps them unchanged. `SmtpEmailSender` and `NullEmailSender` implement both.
2. **IP permits are configurable** (`Login:LoginPermitPerMinute`, `Login:RefreshPermitPerMinute`, default 30), like the existing `Registration:RateLimitPermitPerWindow`. Tests share one server and IP partition, so the test factory raises them; the rate-limit test sets 30.
3. **The HTTPS guard runs outside Development only.** Docker Compose and the `.http` file use plain HTTP in Development. Production has no exception.
4. **OTP exhaustion 429 has no `Retry-After`.** Waiting does not help; the client starts a new login.
5. **Audit outcome `rejected`** is added to `LoginChallenge` for not found, already consumed, or method mismatch.
6. **`EmailDeliveryException` is not mapped by the exception handler.** Login and resend handle SMTP failure themselves; registration already catches it.

## File map

**Infrastructure** (`src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/`)

| File | Responsibility |
| --- | --- |
| `Users/UserStatus.cs` (modify) | add `Blocked`, `Deleting`, `Deleted` |
| `Authentication/JwtOptions.cs` | `Jwt` section |
| `Authentication/LoginOptions.cs` | `Login` section |
| `Authentication/JwtTokenService.cs` | issue and validate access/refresh JWTs |
| `Authentication/FailedLoginLimiter.cs` | 5 failures per email+IP per 15 min |
| `Authentication/AuthAudit.cs` | structured audit lines, `EmailRef` |
| `Authentication/LoginChallenge.cs` | entity + `ConsumedReason` |
| `Authentication/ILoginEmailSender.cs` | sign-in email port |
| `Authentication/LoginService.cs` | login, confirm, resend, refresh + result records |
| `Registration/SmtpEmailSender.cs`, `Registration/IEmailSender.cs` (modify) | implement `ILoginEmailSender` |
| `AppDbContext.cs` (modify) | map `login_challenges` |
| `Migrations/*_LoginChallenges.cs` (generated) | table + partial unique index |

**API** (`src/FEDept.BackendCourse.GroupA1.Api.Template/`)

| File | Responsibility |
| --- | --- |
| `Authentication/FrontendOptions.cs` | `Frontend` section |
| `Authentication/AuthConfigurationValidator.cs` | startup validation of all auth settings |
| `Authentication/AuthCookies.cs` | set/clear both cookies |
| `Authentication/AccessCookieAuthenticationHandler.cs` | shared access check |
| `Authentication/DependencyFailureHandler.cs` | DB/signing failure → 503 |
| `Authentication/CsrfMiddleware.cs` | Origin + `X-CSRF-Protection` check |
| `Authentication/HttpsOnlyMiddleware.cs` | plain HTTP on `/auth/*` → 400 |
| `Contracts/ErrorResponse.cs` | `ErrorResponse`, `RetryAfterResponse`, `ErrorResponses` |
| `Contracts/LoginRequest.cs`, `LoginConfirmRequest.cs`, `LoginResendRequest.cs`, `LoginChallengeResponse.cs` | DTOs |
| `Controllers/LoginController.cs` | the five endpoints |
| `Program.cs` (modify) | wiring |
| `FEDept.BackendCourse.GroupA1.Api.Template.csproj` (modify) | `UserSecretsId` |

**Tests** (`tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/`)

| File | Covers |
| --- | --- |
| `RegistrationTestFactory.cs` (modify) | random auth keys, high IP permits |
| `Auth/AuthTestKit.cs` | users, clients, cookies, fakes, log capture |
| `Auth/AuthConfigurationTests.cs` | startup validation |
| `Auth/JwtTokenServiceTests.cs` | issue + failure categories |
| `Auth/FailedLoginLimiterTests.cs` | pair limiter |
| `Auth/DependencyFailureHandlerTests.cs` | 503 mapping |
| `Auth/DirectLoginTests.cs` | direct login, neutral 401, rate limits |
| `Auth/SessionTests.cs` | refresh, logout, access check |
| `Auth/OtpChallengeTests.cs` | OTP login, confirm, resend |
| `Auth/MagicLinkChallengeTests.cs` | magic-link login and confirm |
| `Auth/BrowserProtectionTests.cs` | CSRF, CORS, HTTPS |
| `Auth/AuthAuditTests.cs` | audit content, no secrets |
| `Auth/ProtectedTestController.cs` | test-only `[Authorize]` route |

Commands used throughout (run from the repository root):

```bash
dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~<TestClass>"
```

Tests need Docker running (Testcontainers).

---

### Task 1: Options, startup validation, user statuses

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Users/UserStatus.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/JwtOptions.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/LoginOptions.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/FrontendOptions.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/AuthConfigurationValidator.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.csproj`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/RegistrationTestFactory.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/AuthConfigurationTests.cs`

- [ ] **Step 1: Add the JWT package**

```bash
dotnet add src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure package Microsoft.IdentityModel.JsonWebTokens --version 8.23.0
```

- [ ] **Step 2: Extend `UserStatus`**

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;

public enum UserStatus
{
    Pending,
    Active,
    Blocked,
    Deleting,
    Deleted
}
```

Status is stored as a string, so no migration is needed.

- [ ] **Step 3: Create the option classes**

`Infrastructure/Authentication/JwtOptions.cs`:

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class JwtOptions
{
    public string AccessSecret { get; set; } = string.Empty;

    public string RefreshSecret { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;
}
```

`Infrastructure/Authentication/LoginOptions.cs`:

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class LoginOptions
{
    public bool ConfirmationEnabled { get; set; }

    public ChallengeMethod ConfirmationMethod { get; set; } = ChallengeMethod.Otp;

    public string ChallengeHmacKey { get; set; } = string.Empty;

    public string AuditHmacKey { get; set; } = string.Empty;

    public string MagicLinkBaseUrl { get; set; } = string.Empty;

    public int LoginPermitPerMinute { get; set; } = 30;

    public int RefreshPermitPerMinute { get; set; } = 30;
}
```

`Api/Authentication/FrontendOptions.cs`:

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class FrontendOptions
{
    public string Origin { get; set; } = string.Empty;

    public bool CrossSite { get; set; }
}
```

- [ ] **Step 4: Write the failing validation tests**

`tests/.../Auth/AuthConfigurationTests.cs`:

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class AuthConfigurationTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
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
    [InlineData("")]
    [InlineData("short-key")]
    [InlineData("0123456789012345678901234567890")]
    public void Errors_ShortAccessSecret_IsReported(string access)
    {
        var errors = AuthConfigurationValidator.Errors(Jwt(access, KeyB), Login(KeyC, KeyD), new FrontendOptions(), false);

        Assert.Contains(errors, error => error.Contains("Jwt:AccessSecret", StringComparison.Ordinal));
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
    [InlineData("", false)]
    [InlineData("/login/confirm", false)]
    [InlineData("http://localhost:3000/login/confirm", false)]
    [InlineData("https://app.example.com/login/confirm#x", false)]
    [InlineData("http://localhost:3000/login/confirm", true)]
    [InlineData("https://app.example.com/login/confirm", false)]
    public void Errors_MagicLinkBaseUrl_RequiresAbsoluteHttpsUrl(string url, bool isDevelopment)
    {
        var login = Login(KeyC, KeyD);
        login.ConfirmationMethod = ChallengeMethod.MagicLink;
        login.MagicLinkBaseUrl = url;
        var valid = url is "https://app.example.com/login/confirm" || (isDevelopment && url.StartsWith("http://", StringComparison.Ordinal));

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
```

- [ ] **Step 5: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~AuthConfigurationTests"`
Expected: build FAIL, `AuthConfigurationValidator` does not exist.

- [ ] **Step 6: Implement the validator**

`Api/Authentication/AuthConfigurationValidator.cs`:

```csharp
using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class AuthConfigurationValidator(
    IOptions<JwtOptions> jwt,
    IOptions<FrontendOptions> frontend,
    IHostEnvironment environment) : IValidateOptions<LoginOptions>
{
    public const int MinKeyBytes = 32;

    public ValidateOptionsResult Validate(string? name, LoginOptions options)
    {
        var errors = Errors(jwt.Value, options, frontend.Value, environment.IsDevelopment()).ToList();
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    public static IEnumerable<string> Errors(JwtOptions jwt, LoginOptions login, FrontendOptions frontend, bool isDevelopment)
    {
        (string Name, string Value)[] keys =
        [
            ("Jwt:AccessSecret", jwt.AccessSecret),
            ("Jwt:RefreshSecret", jwt.RefreshSecret),
            ("Login:ChallengeHmacKey", login.ChallengeHmacKey),
            ("Login:AuditHmacKey", login.AuditHmacKey)
        ];
        foreach (var key in keys.Where(key => Encoding.UTF8.GetByteCount(key.Value ?? string.Empty) < MinKeyBytes))
        {
            yield return $"{key.Name} must be at least {MinKeyBytes} bytes.";
        }

        if (keys.Select(key => key.Value).Distinct(StringComparer.Ordinal).Count() != keys.Length)
        {
            yield return "Jwt:AccessSecret, Jwt:RefreshSecret, Login:ChallengeHmacKey and Login:AuditHmacKey must all differ.";
        }

        if (string.IsNullOrWhiteSpace(jwt.Issuer))
        {
            yield return "Jwt:Issuer is required.";
        }

        if (string.IsNullOrWhiteSpace(jwt.Audience))
        {
            yield return "Jwt:Audience is required.";
        }

        if (!Enum.IsDefined(login.ConfirmationMethod))
        {
            yield return "Login:ConfirmationMethod must be Otp or MagicLink.";
        }

        if (login.ConfirmationMethod == ChallengeMethod.MagicLink && !IsMagicLinkBaseUrl(login.MagicLinkBaseUrl, isDevelopment))
        {
            yield return "Login:MagicLinkBaseUrl must be an absolute https URL without a fragment when the magic link method is enabled.";
        }

        if (frontend.Origin.Length > 0 && !IsOrigin(frontend.Origin))
        {
            yield return "Frontend:Origin must be an exact origin such as https://app.example.com.";
        }
    }

    private static bool IsMagicLinkBaseUrl(string value, bool isDevelopment) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || (isDevelopment && uri.Scheme == Uri.UriSchemeHttp))
        && uri.Fragment.Length == 0;

    private static bool IsOrigin(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
        && string.Equals(value, uri.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal);
}
```

- [ ] **Step 7: Register options in `Program.cs`**

Add usings at the top:

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
```

Insert after the `builder.Services.AddOptions<SmtpOptions>()…;` statement:

```csharp
builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection("Jwt"));
builder.Services.AddOptions<FrontendOptions>()
    .Bind(builder.Configuration.GetSection("Frontend"));
builder.Services.AddOptions<LoginOptions>()
    .Bind(builder.Configuration.GetSection("Login"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<LoginOptions>, AuthConfigurationValidator>();
```

- [ ] **Step 8: Give the existing test factory valid keys**

In `RegistrationTestFactory.ConfigureWebHost`, extend the in-memory dictionary (add `using System.Security.Cryptography;`):

```csharp
                ["ConnectionStrings:Default"] = _postgres.GetConnectionString(),
                ["Database:ApplyMigrations"] = "true",
                ["Jwt:AccessSecret"] = _accessSecret,
                ["Jwt:RefreshSecret"] = _refreshSecret,
                ["Jwt:Issuer"] = "groupa1-api-tests",
                ["Jwt:Audience"] = "groupa1-web-tests",
                ["Login:ChallengeHmacKey"] = _challengeKey,
                ["Login:AuditHmacKey"] = _auditKey,
                ["Login:MagicLinkBaseUrl"] = "https://app.example.test/login/confirm",
                ["Login:LoginPermitPerMinute"] = "10000",
                ["Login:RefreshPermitPerMinute"] = "10000"
```

and add to the class. The keys are fields so every `WithWebHostBuilder` copy of the factory shares them; `ConfigureWebHost` runs again for each copy.

```csharp
    private readonly string _accessSecret = NewKey();
    private readonly string _refreshSecret = NewKey();
    private readonly string _challengeKey = NewKey();
    private readonly string _auditKey = NewKey();

    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
```

- [ ] **Step 9: Add user secrets**

```bash
dotnet user-secrets init --project src/FEDept.BackendCourse.GroupA1.Api.Template
```

Expected: `<UserSecretsId>` appears in the API `.csproj`.

- [ ] **Step 10: Run the new and the existing tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS, including every registration test.

- [ ] **Step 11: Commit**

```bash
git add src tests
git commit -m "feat: auth options with startup key validation and user statuses"
```

### Task 2: `JwtTokenService`

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/JwtTokenService.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/JwtTokenServiceTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class JwtTokenServiceTests
{
    private static readonly JwtOptions Options = new()
    {
        AccessSecret = new string('a', 32),
        RefreshSecret = new string('r', 32),
        Issuer = "api",
        Audience = "web"
    };

    private readonly JwtTokenService _service = new(Microsoft.Extensions.Options.Options.Create(Options));

    [Fact]
    public async Task Issue_ProducesAccessAndRefreshThatValidateForTheirOwnUse()
    {
        var userId = Guid.NewGuid();

        var pair = _service.Issue(userId);

        Assert.Equal(new TokenValidation.Ok(userId), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
        Assert.Equal(new TokenValidation.Ok(userId), await _service.ValidateAsync(pair.RefreshToken, TokenUse.Refresh));
    }

    [Fact]
    public void Issue_WritesOnlyTheContractClaims()
    {
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

        var pair = _service.Issue(Guid.NewGuid(), issuedAt);

        var access = new JsonWebToken(pair.AccessToken);
        var refresh = new JsonWebToken(pair.RefreshToken);
        Assert.Equal("HS256", access.Alg);
        Assert.Equal(["aud", "exp", "iat", "iss", "sub", "token_use"], access.Claims.Select(claim => claim.Type).Order().ToArray());
        Assert.Equal("access", access.GetClaim("token_use").Value);
        Assert.Equal("refresh", refresh.GetClaim("token_use").Value);
        Assert.Equal(900, access.ValidTo.Subtract(access.IssuedAt).TotalSeconds);
        Assert.Equal(2592000, refresh.ValidTo.Subtract(refresh.IssuedAt).TotalSeconds);
    }

    [Fact]
    public async Task Validate_RefreshAsAccess_FailsWithSignature()
    {
        var pair = _service.Issue(Guid.NewGuid());

        Assert.Equal(new TokenValidation.Fail("signature"), await _service.ValidateAsync(pair.RefreshToken, TokenUse.Access));
    }

    [Theory]
    [InlineData(null, "missing")]
    [InlineData("", "missing")]
    [InlineData("not-a-jwt", "malformed")]
    public async Task Validate_BadInput_ReturnsCategory(string? token, string category)
    {
        Assert.Equal(new TokenValidation.Fail(category), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_Expired_ReturnsExpired()
    {
        var pair = _service.Issue(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-16));

        Assert.Equal(new TokenValidation.Fail("expired"), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_WithinClockSkew_IsAccepted()
    {
        var userId = Guid.NewGuid();
        var pair = _service.Issue(userId, DateTimeOffset.UtcNow.AddMinutes(-15).AddSeconds(-20));

        Assert.Equal(new TokenValidation.Ok(userId), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_OtherIssuer_ReturnsClaims()
    {
        var other = new JwtTokenService(Microsoft.Extensions.Options.Options.Create(new JwtOptions
        {
            AccessSecret = Options.AccessSecret,
            RefreshSecret = Options.RefreshSecret,
            Issuer = "someone-else",
            Audience = Options.Audience
        }));

        var pair = other.Issue(Guid.NewGuid());

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_AccessKeyWithRefreshUse_ReturnsTokenUse()
    {
        var token = Sign(Options.AccessSecret, SecurityAlgorithms.HmacSha256, new Dictionary<string, object>
        {
            ["sub"] = Guid.NewGuid().ToString(),
            ["token_use"] = "refresh"
        });

        Assert.Equal(new TokenValidation.Fail("token_use"), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_NonGuidSub_ReturnsClaims()
    {
        var token = Sign(Options.AccessSecret, SecurityAlgorithms.HmacSha256, new Dictionary<string, object>
        {
            ["sub"] = "user-42",
            ["token_use"] = "access"
        });

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_OtherAlgorithmOrUnsigned_ReturnsSignature()
    {
        var claims = new Dictionary<string, object> { ["sub"] = Guid.NewGuid().ToString(), ["token_use"] = "access" };
        var hs512 = Sign(Options.AccessSecret + Options.AccessSecret, SecurityAlgorithms.HmacSha512, claims);
        var unsigned = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Options.Issuer,
            Audience = Options.Audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = claims
        });

        Assert.Equal(new TokenValidation.Fail("signature"), await _service.ValidateAsync(hs512, TokenUse.Access));
        Assert.Equal(new TokenValidation.Fail("signature"), await _service.ValidateAsync(unsigned, TokenUse.Access));
    }

    private static string Sign(string key, string algorithm, Dictionary<string, object> claims) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Options.Issuer,
            Audience = Options.Audience,
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), algorithm)
        });
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~JwtTokenServiceTests"`
Expected: build FAIL, `JwtTokenService` does not exist.

- [ ] **Step 3: Implement `JwtTokenService`**

```csharp
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public enum TokenUse
{
    Access,
    Refresh
}

public sealed record TokenPair(string AccessToken, string RefreshToken);

public abstract record TokenValidation
{
    public sealed record Ok(Guid UserId) : TokenValidation;

    public sealed record Fail(string Category) : TokenValidation;
}

public sealed class TokenSigningException(Exception innerException) : Exception("Token signing failed.", innerException);

public sealed class JwtTokenService(IOptions<JwtOptions> options)
{
    public static readonly TimeSpan AccessLifetime = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(30);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    // no implicit nbf/iat/exp: the contract fixes the claim set
    private static readonly JsonWebTokenHandler Handler = new() { SetDefaultTimesOnTokenCreation = false };

    public TokenPair Issue(Guid userId) => Issue(userId, DateTimeOffset.UtcNow);

    public TokenPair Issue(Guid userId, DateTimeOffset issuedAt)
    {
        try
        {
            return new TokenPair(Create(userId, TokenUse.Access, issuedAt), Create(userId, TokenUse.Refresh, issuedAt));
        }
        catch (Exception exception)
        {
            throw new TokenSigningException(exception);
        }
    }

    public async Task<TokenValidation> ValidateAsync(string? token, TokenUse use)
    {
        if (string.IsNullOrEmpty(token))
        {
            return new TokenValidation.Fail("missing");
        }

        var result = await Handler.ValidateTokenAsync(token, Parameters(use));
        if (!result.IsValid)
        {
            return new TokenValidation.Fail(Categorize(result.Exception));
        }

        if (!result.Claims.ContainsKey(JwtRegisteredClaimNames.Iat)
            || !result.Claims.TryGetValue(JwtRegisteredClaimNames.Sub, out var sub)
            || !Guid.TryParse(sub as string, out var userId)
            || userId == Guid.Empty)
        {
            return new TokenValidation.Fail("claims");
        }

        return result.Claims.TryGetValue("token_use", out var tokenUse) && Equals(tokenUse, Name(use))
            ? new TokenValidation.Ok(userId)
            : new TokenValidation.Fail("token_use");
    }

    private string Create(Guid userId, TokenUse use, DateTimeOffset issuedAt) =>
        Handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            IssuedAt = issuedAt.UtcDateTime,
            Expires = (issuedAt + (use == TokenUse.Access ? AccessLifetime : RefreshLifetime)).UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = userId.ToString(),
                ["token_use"] = Name(use)
            },
            SigningCredentials = new SigningCredentials(Key(use), SecurityAlgorithms.HmacSha256)
        });

    private TokenValidationParameters Parameters(TokenUse use) => new()
    {
        ValidIssuer = options.Value.Issuer,
        ValidAudience = options.Value.Audience,
        IssuerSigningKey = Key(use),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = ClockSkew
    };

    private SymmetricSecurityKey Key(TokenUse use) => new(Encoding.UTF8.GetBytes(
        use == TokenUse.Access ? options.Value.AccessSecret : options.Value.RefreshSecret));

    private static string Name(TokenUse use) => use == TokenUse.Access ? "access" : "refresh";

    private static string Categorize(Exception? exception) => exception switch
    {
        SecurityTokenExpiredException => "expired",
        SecurityTokenInvalidSignatureException or SecurityTokenInvalidAlgorithmException => "signature",
        SecurityTokenInvalidIssuerException or SecurityTokenInvalidAudienceException
            or SecurityTokenNoExpirationException or SecurityTokenInvalidLifetimeException
            or SecurityTokenNotYetValidException => "claims",
        _ => "malformed"
    };
}
```

`SecurityTokenSignatureKeyNotFoundException` derives from `SecurityTokenInvalidSignatureException`, so a wrong key also maps to `signature`.

- [ ] **Step 4: Run the tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~JwtTokenServiceTests"`
Expected: PASS. If `Validate_OtherAlgorithmOrUnsigned_ReturnsSignature` reports `malformed` for one token, log `result.Exception.GetType()` and add that exception type to the `signature` arm — do not loosen the assertion.

- [ ] **Step 5: Register the service**

In `Program.cs`, after the `IValidateOptions<LoginOptions>` registration:

```csharp
builder.Services.AddSingleton<JwtTokenService>();
```

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: JWT access and refresh issue and validation"
```

### Task 3: Error contracts, `AuthAudit`, 503 handler

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/ErrorResponse.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/AuthAudit.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/DependencyFailureHandler.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/DependencyFailureHandlerTests.cs`

- [ ] **Step 1: Create the error contracts**

```csharp
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
```

- [ ] **Step 2: Create `AuthAudit`**

```csharp
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// never pass emails, secrets, tokens, cookies or bodies here; RequestId comes from the logging scope
public sealed class AuthAudit(ILogger<AuthAudit> logger, IOptions<LoginOptions> options)
{
    public string EmailRef(string normalizedEmail)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(options.Value.AuditHmacKey));
        return Base64Url.EncodeToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(normalizedEmail)));
    }

    public void Login(Guid? userId, string? emailRef, string outcome) =>
        logger.LogInformation("Auth audit EventName={EventName} UserId={UserId} EmailRef={EmailRef} Outcome={Outcome}",
            "Login", userId, userId is null ? emailRef : null, outcome);

    public void Challenge(Guid? userId, Guid attemptId, ChallengeMethod? method, string outcome) =>
        logger.LogInformation("Auth audit EventName={EventName} UserId={UserId} AttemptId={AttemptId} Method={Method} Outcome={Outcome}",
            "LoginChallenge", userId, attemptId, method?.ToContractName(), outcome);

    public void Refresh(Guid? userId, string outcome, string? category) =>
        logger.LogInformation("Auth audit EventName={EventName} UserId={UserId} Outcome={Outcome} Category={Category}",
            "Refresh", userId, outcome, category);

    public void Logout() =>
        logger.LogInformation("Auth audit EventName={EventName} Outcome={Outcome}", "Logout", "success");

    public void AccessRejected(string category) =>
        logger.LogInformation("Auth audit EventName={EventName} Outcome={Outcome} Category={Category}",
            "AccessRejected", "failure", category);

    public void DependencyUnavailable(string dependency) =>
        logger.LogWarning("Auth audit EventName={EventName} Outcome={Outcome} Category={Category}",
            "DependencyUnavailable", "failure", dependency);

    public void CsrfRejected(string reason) =>
        logger.LogWarning("Auth audit EventName={EventName} Outcome={Outcome} Category={Category}",
            "CsrfRejected", "failure", reason);
}
```

- [ ] **Step 3: Write the failing handler test**

```csharp
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class DependencyFailureHandlerTests
{
    private readonly DependencyFailureHandler _handler = new(
        new AuthAudit(NullLogger<AuthAudit>.Instance, Options.Create(new LoginOptions { AuditHmacKey = new string('k', 32) })));

    public static TheoryData<Exception> DependencyFailures() => new()
    {
        new TokenSigningException(new InvalidOperationException()),
        new NpgsqlException("connection refused"),
        new InvalidOperationException("wrapped", new NpgsqlException("connection refused"))
    };

    [Theory]
    [MemberData(nameof(DependencyFailures))]
    public async Task DependencyFailure_Returns503ServiceUnavailable(Exception exception)
    {
        var context = new DefaultHttpContext { Response = { Body = new MemoryStream() } };

        var handled = await _handler.TryHandleAsync(context, exception, CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(503, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal("service_unavailable", body.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task OtherException_IsNotHandled()
    {
        var handled = await _handler.TryHandleAsync(new DefaultHttpContext(), new InvalidOperationException(), CancellationToken.None);

        Assert.False(handled);
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~DependencyFailureHandlerTests"`
Expected: build FAIL, `DependencyFailureHandler` does not exist.

- [ ] **Step 5: Implement the handler**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class DependencyFailureHandler(AuthAudit audit) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var dependency = exception is TokenSigningException ? "signing" : IsDatabaseUnavailable(exception) ? "db" : null;
        if (dependency is null)
        {
            return false;
        }

        audit.DependencyUnavailable(dependency);
        httpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await httpContext.Response.WriteAsJsonAsync(ErrorResponses.ServiceUnavailable, cancellationToken);
        return true;
    }

    // a constraint violation is a bug (500); only connection-level or transient errors are an outage
    private static bool IsDatabaseUnavailable(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is NpgsqlException npgsql)
            {
                return npgsql is not PostgresException || npgsql.IsTransient;
            }
        }

        return false;
    }
}
```

- [ ] **Step 6: Wire it in `Program.cs`**

After `builder.Services.AddSingleton<JwtTokenService>();`:

```csharp
builder.Services.AddSingleton<AuthAudit>();
builder.Services.AddExceptionHandler<DependencyFailureHandler>();
builder.Services.AddProblemDetails();
```

Before `app.UseHttpsRedirection();`:

```csharp
app.UseExceptionHandler();
```

- [ ] **Step 7: Run all tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add src tests
git commit -m "feat: auth error contracts, audit helper and 503 dependency handler"
```

### Task 4: `FailedLoginLimiter`

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/FailedLoginLimiter.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/FailedLoginLimiterTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class FailedLoginLimiterTests
{
    private readonly FailedLoginLimiter _limiter = new(new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public void FiveFailedAttempts_AllowedThenSixthBlocked()
    {
        for (var i = 0; i < 5; i++)
        {
            Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.1"));
        }

        var retryAfter = _limiter.TryBeginAttempt("ref", "10.0.0.1");
        Assert.NotNull(retryAfter);
        Assert.InRange(retryAfter.Value, 1, 900);
    }

    [Fact]
    public void Block_AppliesToThePairOnly()
    {
        for (var i = 0; i < 5; i++)
        {
            _limiter.TryBeginAttempt("ref", "10.0.0.1");
        }

        Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.2"));
        Assert.Null(_limiter.TryBeginAttempt("other", "10.0.0.1"));
    }

    [Fact]
    public void ReleasedAttempts_DoNotCount()
    {
        for (var i = 0; i < 10; i++)
        {
            Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.1"));
            _limiter.Release("ref", "10.0.0.1");
        }

        Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.1"));
    }

    [Fact]
    public void ConcurrentAttempts_NeverExceedTheLimit()
    {
        var allowed = 0;

        Parallel.For(0, 50, _ =>
        {
            if (_limiter.TryBeginAttempt("ref", "10.0.0.1") is null)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(FailedLoginLimiter.MaxFailures, allowed);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~FailedLoginLimiterTests"`
Expected: build FAIL, `FailedLoginLimiter` does not exist.

- [ ] **Step 3: Implement**

```csharp
using Microsoft.Extensions.Caching.Memory;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// shortcut: in-memory and per instance; move to a shared store when the API scales out
public sealed class FailedLoginLimiter(IMemoryCache cache)
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    // one gate for get-or-create, prune and count: IMemoryCache.GetOrCreate is not atomic
    private readonly Lock _gate = new();

    // reserves a slot that counts as a failure until Release; returns the seconds to wait when the pair is blocked
    public int? TryBeginAttempt(string emailRef, string clientIp)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_gate)
        {
            var attempts = cache.GetOrCreate(Key(emailRef, clientIp), entry =>
            {
                entry.SlidingExpiration = Window;
                return new List<DateTimeOffset>();
            })!;
            attempts.RemoveAll(at => at + Window <= now);
            if (attempts.Count >= MaxFailures)
            {
                return (int)Math.Ceiling((attempts[0] + Window - now).TotalSeconds);
            }

            attempts.Add(now);
            return null;
        }
    }

    // a successful check (or an outage) gives the reserved slot back
    public void Release(string emailRef, string clientIp)
    {
        lock (_gate)
        {
            if (cache.TryGetValue(Key(emailRef, clientIp), out List<DateTimeOffset>? attempts) && attempts is { Count: > 0 })
            {
                attempts.RemoveAt(attempts.Count - 1);
            }
        }
    }

    private static string Key(string emailRef, string clientIp) => $"failed-login:{emailRef}:{clientIp}";
}
```

- [ ] **Step 4: Run the tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~FailedLoginLimiterTests"`
Expected: PASS.

- [ ] **Step 5: Register**

In `Program.cs`, after `builder.Services.AddSingleton<AuthAudit>();`:

```csharp
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<FailedLoginLimiter>();
```

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: failed login limiter per email and IP"
```

### Task 5: Direct login

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/LoginRequest.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/AuthCookies.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/LoginService.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/LoginController.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Create: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/AuthTestKit.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/DirectLoginTests.cs`

- [ ] **Step 1: Create the shared test kit**

```csharp
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

internal static class AuthTestKit
{
    // trailing space: login must not trim or normalize the password
    public const string Password = "Login password 42 ";
    private static readonly Lazy<string> PasswordHash = new(() => PasswordHasher.Hash(Password));

    public static string NewEmail() => $"login-{Guid.NewGuid():N}@example.com";

    public static WebApplicationFactory<Program> WithSettings(
        this RegistrationTestFactory factory,
        IDictionary<string, string?> settings,
        Action<IServiceCollection>? services = null) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(settings));
            if (services is not null)
            {
                builder.ConfigureTestServices(services);
            }
        });

    public static HttpClient CreateClient(WebApplicationFactory<Program> app, string baseAddress = "https://localhost") =>
        app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            HandleCookies = false,
            AllowAutoRedirect = false
        });

    public static async Task<Guid> CreateUserAsync(IServiceProvider services, string email, UserStatus status = UserStatus.Active)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            PasswordHash = PasswordHash.Value,
            Status = status,
            CreatedAt = now,
            UpdatedAt = now
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user.Id;
    }

    public static async Task SetStatusAsync(IServiceProvider services, Guid userId, UserStatus status)
    {
        using var scope = services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users
            .Where(user => user.Id == userId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(user => user.Status, status));
    }

    public static Task<HttpResponseMessage> LoginAsync(HttpClient client, string email, string password = Password) =>
        client.PostAsJsonAsync("/auth/login", new { email, password });

    public static Task<HttpResponseMessage> PostWithCookieAsync(HttpClient client, string path, string? cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return client.SendAsync(request);
    }

    public static string[] SetCookies(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToArray() : [];

    public static string SetCookie(HttpResponseMessage response, string name)
    {
        var matches = SetCookies(response).Where(header => header.StartsWith(name + "=", StringComparison.Ordinal)).ToArray();
        Assert.Single(matches);
        return matches[0];
    }

    public static string CookieValue(HttpResponseMessage response, string name)
    {
        var header = SetCookie(response, name);
        return header[(name.Length + 1)..header.IndexOf(';')];
    }

    public static void AssertSessionCookies(HttpResponseMessage response, string sameSite = "strict")
    {
        var access = SetCookie(response, "access_token").ToLowerInvariant();
        var refresh = SetCookie(response, "refresh_token").ToLowerInvariant();
        Assert.Contains("path=/;", access, StringComparison.Ordinal);
        Assert.Contains("max-age=900", access, StringComparison.Ordinal);
        Assert.Contains("path=/auth/refresh", refresh, StringComparison.Ordinal);
        Assert.Contains("max-age=2592000", refresh, StringComparison.Ordinal);
        foreach (var header in new[] { access, refresh })
        {
            Assert.Contains("secure", header, StringComparison.Ordinal);
            Assert.Contains("httponly", header, StringComparison.Ordinal);
            Assert.Contains($"samesite={sameSite}", header, StringComparison.Ordinal);
            Assert.DoesNotContain("domain=", header, StringComparison.Ordinal);
        }
    }
}
```

- [ ] **Step 2: Write the failing tests**

`Auth/DirectLoginTests.cs`:

```csharp
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class DirectLoginTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    [Fact]
    public async Task Login_ActiveUser_Returns204WithBothCookiesAndNoBody()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);

        using var response = await LoginAsync(client, email);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        AssertSessionCookies(response);
    }

    [Fact]
    public async Task Login_NormalizesEmail()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);

        using var response = await LoginAsync(client, $"  {email.ToUpperInvariant()} ");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Login_DoesNotTrimPassword()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);

        using var response = await LoginAsync(client, email, Password.Trim());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_UnknownWrongPasswordAndInactiveStatuses_ReturnIdenticalNeutral401()
    {
        using var client = CreateClient(factory);
        var active = NewEmail();
        await CreateUserAsync(factory.Services, active);
        var attempts = new List<(string Email, string Password)> { (NewEmail(), Password), (active, "wrong password 1") };
        foreach (var status in new[] { UserStatus.Pending, UserStatus.Blocked, UserStatus.Deleting, UserStatus.Deleted })
        {
            var email = NewEmail();
            await CreateUserAsync(factory.Services, email, status);
            attempts.Add((email, Password));
        }

        var bodies = new List<string>();
        foreach (var (email, password) in attempts)
        {
            using var response = await LoginAsync(client, email, password);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(SetCookies(response));
            bodies.Add(await response.Content.ReadAsStringAsync());
        }

        Assert.Single(bodies.Distinct());
        using var body = JsonDocument.Parse(bodies[0]);
        Assert.Equal("invalid_credentials", body.RootElement.GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("{\"password\":\"x\"}")]
    [InlineData("{\"email\":\"not-an-email\",\"password\":\"x\"}")]
    [InlineData("{\"email\":\"user@example.com\"}")]
    public async Task Login_InvalidFormat_Returns400(string json)
    {
        using var client = CreateClient(factory);

        using var response = await client.PostAsync("/auth/login", new StringContent(json, System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_SixthCheckAfterFiveFailures_Returns429EvenWithCorrectPassword()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);
        for (var i = 0; i < 5; i++)
        {
            using var failed = await LoginAsync(client, email, "wrong password 1");
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        using var response = await LoginAsync(client, email);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(response.Headers.RetryAfter is not null);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("retryAfterSeconds").GetInt32() > 0);
    }

    [Fact]
    public async Task Login_ThirtyFirstRequestPerMinuteFromOneIp_Returns429()
    {
        using var app = factory.WithSettings(new Dictionary<string, string?> { ["Login:LoginPermitPerMinute"] = "30" });
        using var client = CreateClient(app);
        for (var i = 0; i < 30; i++)
        {
            using var allowed = await client.PostAsJsonAsync("/auth/login", new { password = "x" });
            Assert.Equal(HttpStatusCode.BadRequest, allowed.StatusCode);
        }

        using var response = await client.PostAsJsonAsync("/auth/login", new { password = "x" });

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(response.Headers.RetryAfter is not null);
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~DirectLoginTests"`
Expected: FAIL — `/auth/login` returns 404.

- [ ] **Step 4: Create `LoginRequest`**

```csharp
using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record LoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;

    // kept exactly as sent: no trimming or normalization
    [Required]
    public string Password { get; init; } = string.Empty;
}
```

- [ ] **Step 5: Create `AuthCookies`**

```csharp
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
```

- [ ] **Step 6: Create `LoginService` (direct login only for now)**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class LoginService(
    AppDbContext db,
    IOptionsSnapshot<LoginOptions> options,
    JwtTokenService tokens,
    FailedLoginLimiter failedLogins,
    AuthAudit audit)
{
    // prepared once; a missing account still costs one BCrypt check
    private static readonly string DummyHash = PasswordHasher.Hash(Guid.NewGuid().ToString());

    public async Task<LoginResult> LoginAsync(string email, string password, string clientIp, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        var emailRef = audit.EmailRef(normalizedEmail);
        // reserves a failure slot before BCrypt, so concurrent guesses cannot exceed the limit
        if (failedLogins.TryBeginAttempt(emailRef, clientIp) is { } wait)
        {
            audit.Login(null, emailRef, "rate_limited_pair");
            return new LoginResult.TooManyRequests(wait);
        }

        User? user;
        bool valid;
        try
        {
            user = await db.Users.AsNoTracking().SingleOrDefaultAsync(item => item.Email == normalizedEmail, ct);
            valid = PasswordHasher.Verify(password, user?.PasswordHash ?? DummyHash) && user is { Status: UserStatus.Active };
        }
        catch
        {
            // an outage is not a failed check
            failedLogins.Release(emailRef, clientIp);
            throw;
        }

        if (!valid || user is null)
        {
            // the reserved slot stays as the recorded failure
            audit.Login(user?.Id, emailRef, "invalid_credentials");
            return LoginResult.InvalidCredentials.Instance;
        }

        failedLogins.Release(emailRef, clientIp);

        var pair = tokens.Issue(user.Id);
        audit.Login(user.Id, null, "success");
        return new LoginResult.SignedIn(pair);
    }
}

public abstract record LoginResult
{
    public sealed record SignedIn(TokenPair Tokens) : LoginResult;

    public sealed record InvalidCredentials : LoginResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }

    public sealed record TooManyRequests(int RetryAfterSeconds) : LoginResult;
}
```

- [ ] **Step 7: Create `LoginController` (login only for now)**

```csharp
using System.Globalization;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Controllers;

[ApiController]
[Route("auth")]
public sealed class LoginController(LoginService loginService, AuthCookies cookies) : ControllerBase
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
```

- [ ] **Step 8: Wire services and the rate limiter in `Program.cs`**

Add `using System.Globalization;` and `using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;` to the top. After `builder.Services.AddSingleton<FailedLoginLimiter>();`:

```csharp
builder.Services.AddSingleton<AuthCookies>();
builder.Services.AddScoped<LoginService>();
```

Replace the whole `builder.Services.AddRateLimiter(...)` statement with:

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("registration", context =>
    {
        var permitLimit = context.RequestServices.GetRequiredService<IOptions<RegistrationOptions>>().Value.RateLimitPermitPerWindow;
        return PerIpPerMinute(context, "registration", permitLimit);
    });
    options.AddPolicy("login", context => PerIpPerMinute(context, "login",
        context.RequestServices.GetRequiredService<IOptions<LoginOptions>>().Value.LoginPermitPerMinute));
    options.AddPolicy("refresh", context => PerIpPerMinute(context, "refresh",
        context.RequestServices.GetRequiredService<IOptions<LoginOptions>>().Value.RefreshPermitPerMinute));
    options.OnRejected = async (context, ct) =>
    {
        var http = context.HttpContext;
        var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var wait)
            ? (int)Math.Ceiling(wait.TotalSeconds)
            : 60;
        http.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
        var audit = http.RequestServices.GetRequiredService<AuthAudit>();
        if (http.Request.Path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase))
        {
            audit.Login(null, null, "rate_limited_ip");
        }
        else if (http.Request.Path.Equals("/auth/refresh", StringComparison.OrdinalIgnoreCase))
        {
            audit.Refresh(null, "failure", "rate_limited_ip");
        }

        await http.Response.WriteAsJsonAsync(ErrorResponses.TooManyRequests(retryAfter), ct);
    };
});
```

Add this local function at the end of `Program.cs`, before `public partial class Program;`:

```csharp
static RateLimitPartition<string> PerIpPerMinute(HttpContext context, string policy, int permitLimit) =>
    RateLimitPartition.GetFixedWindowLimiter(
        $"{policy}:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        });
```

Local functions must come before type declarations but may follow `app.Run();`. The policy prefix in the partition key keeps login, refresh and registration counters apart.

- [ ] **Step 9: Run the new and existing tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS, including `RateLimitTests`.

- [ ] **Step 10: Commit**

```bash
git add src tests
git commit -m "feat: direct login with cookies, neutral 401 and rate limits"
```

### Task 6: Refresh and logout

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/LoginService.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/LoginController.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/SessionTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class SessionTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private async Task<(Guid UserId, HttpResponseMessage Login)> SignInAsync(HttpClient client)
    {
        var email = NewEmail();
        var userId = await CreateUserAsync(factory.Services, email);
        var login = await LoginAsync(client, email);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return (userId, login);
    }

    private static async Task AssertInvalidSessionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(SetCookies(response));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_session", body.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Refresh_ValidCookie_Returns204WithNewPair()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={CookieValue(login, "refresh_token")}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        AssertSessionCookies(response);
    }

    [Fact]
    public async Task Refresh_UsedTokenStaysValidUntilExp()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);
        var cookie = $"refresh_token={CookieValue(login, "refresh_token")}";

        using var first = await PostWithCookieAsync(client, "/auth/refresh", cookie);
        using var second = await PostWithCookieAsync(client, "/auth/refresh", cookie);

        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
    }

    [Fact]
    public async Task Refresh_MissingCookie_Returns401()
    {
        using var client = CreateClient(factory);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", null);

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_AccessTokenInRefreshCookie_Returns401()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={CookieValue(login, "access_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_TokenOutsideTheCookie_IsIgnored()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);
        var token = CookieValue(login, "refresh_token");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/auth/refresh?refresh_token={token}")
        {
            Content = JsonContent.Create(new { refresh_token = token })
        };
        request.Headers.Add("Authorization", $"Bearer {token}");

        using var response = await client.SendAsync(request);

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_ExpiredToken_Returns401()
    {
        using var client = CreateClient(factory);
        var userId = await CreateUserAsync(factory.Services, NewEmail());
        var expired = factory.Services.GetRequiredService<JwtTokenService>().Issue(userId, DateTimeOffset.UtcNow.AddDays(-31));

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={expired.RefreshToken}");

        await AssertInvalidSessionAsync(response);
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    [InlineData(UserStatus.Deleted)]
    public async Task Refresh_InactiveUser_Returns401(UserStatus status)
    {
        using var client = CreateClient(factory);
        var (userId, login) = await SignInAsync(client);
        await SetStatusAsync(factory.Services, userId, status);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={CookieValue(login, "refresh_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_ThirtyFirstRequestPerMinuteFromOneIp_Returns429()
    {
        using var app = factory.WithSettings(new Dictionary<string, string?> { ["Login:RefreshPermitPerMinute"] = "30" });
        using var client = CreateClient(app);
        for (var i = 0; i < 30; i++)
        {
            using var allowed = await PostWithCookieAsync(client, "/auth/refresh", null);
            Assert.Equal(HttpStatusCode.Unauthorized, allowed.StatusCode);
        }

        using var response = await PostWithCookieAsync(client, "/auth/refresh", null);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("access_token=garbage; refresh_token=garbage")]
    public async Task Logout_AlwaysReturns204AndClearsBothCookies(string? cookie)
    {
        using var client = CreateClient(factory);

        using var response = await PostWithCookieAsync(client, "/auth/logout", cookie);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        var access = SetCookie(response, "access_token").ToLowerInvariant();
        var refresh = SetCookie(response, "refresh_token").ToLowerInvariant();
        Assert.StartsWith("access_token=;", access, StringComparison.Ordinal);
        Assert.StartsWith("refresh_token=;", refresh, StringComparison.Ordinal);
        Assert.Contains("max-age=0", access, StringComparison.Ordinal);
        Assert.Contains("max-age=0", refresh, StringComparison.Ordinal);
        Assert.Contains("path=/;", access, StringComparison.Ordinal);
        Assert.Contains("path=/auth/refresh", refresh, StringComparison.Ordinal);
        Assert.All(new[] { access, refresh }, header =>
        {
            Assert.Contains("secure", header, StringComparison.Ordinal);
            Assert.Contains("samesite=strict", header, StringComparison.Ordinal);
            Assert.DoesNotContain("domain=", header, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task DatabaseUnavailable_LoginAndRefreshReturn503()
    {
        using var app = factory.WithSettings(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Default"] = "Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none;Timeout=2",
            ["Database:ApplyMigrations"] = "false"
        });
        using var client = CreateClient(app);
        var token = app.Services.GetRequiredService<JwtTokenService>().Issue(Guid.NewGuid()).RefreshToken;

        using var login = await LoginAsync(client, NewEmail());
        using var refresh = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={token}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, login.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, refresh.StatusCode);
        Assert.Empty(SetCookies(refresh));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~SessionTests"`
Expected: FAIL — `/auth/refresh` and `/auth/logout` return 404.

- [ ] **Step 3: Add `RefreshAsync` to `LoginService`**

Insert after `LoginAsync`:

```csharp
    public async Task<TokenPair?> RefreshAsync(string? refreshToken, CancellationToken ct)
    {
        var validation = await tokens.ValidateAsync(refreshToken, TokenUse.Refresh);
        if (validation is TokenValidation.Fail fail)
        {
            audit.Refresh(null, "failure", fail.Category);
            return null;
        }

        var userId = ((TokenValidation.Ok)validation).UserId;
        if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == userId && user.Status == UserStatus.Active, ct))
        {
            audit.Refresh(userId, "failure", "user_inactive");
            return null;
        }

        // stateless: the used refresh token is not stored or denylisted
        var pair = tokens.Issue(userId);
        audit.Refresh(userId, "success", null);
        return pair;
    }
```

- [ ] **Step 4: Add the endpoints to `LoginController`**

Change the constructor to `LoginController(LoginService loginService, AuthCookies cookies, AuthAudit audit)` and insert after `Login`:

```csharp
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
```

- [ ] **Step 5: Run the tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~SessionTests|FullyQualifiedName~DirectLoginTests"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: stateless refresh and idempotent logout"
```

### Task 7: Shared access check

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/AccessCookieAuthenticationHandler.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Create: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/ProtectedTestController.cs`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/SessionTests.cs`

- [ ] **Step 1: Create the test-only protected route**

```csharp
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
```

- [ ] **Step 2: Write the failing tests**

Add to `SessionTests` (add `using Microsoft.AspNetCore.Mvc.Testing;`):

```csharp
    private WebApplicationFactory<Program> WithProtectedRoute() =>
        factory.WithSettings(new Dictionary<string, string?>(), services =>
            services.AddControllers().AddApplicationPart(typeof(ProtectedTestController).Assembly));

    private static Task<HttpResponseMessage> GetProtectedAsync(HttpClient client, string? cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/test/protected");
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return client.SendAsync(request);
    }

    [Fact]
    public async Task Access_ValidCookie_PassesOnlyTheUserId()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var email = NewEmail();
        var userId = await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);

        using var response = await GetProtectedAsync(client, $"access_token={CookieValue(login, "access_token")}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(userId.ToString(), body.GetProperty("userId").GetString());
    }

    [Fact]
    public async Task Access_MissingCookie_Returns401()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);

        using var response = await GetProtectedAsync(client, null);

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Access_RefreshTokenAsAccess_Returns401()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);

        using var response = await GetProtectedAsync(client, $"access_token={CookieValue(login, "refresh_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Access_ExpiredToken_Returns401()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var userId = await CreateUserAsync(app.Services, NewEmail());
        var expired = app.Services.GetRequiredService<JwtTokenService>().Issue(userId, DateTimeOffset.UtcNow.AddMinutes(-16));

        using var response = await GetProtectedAsync(client, $"access_token={expired.AccessToken}");

        await AssertInvalidSessionAsync(response);
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    [InlineData(UserStatus.Deleted)]
    public async Task Access_InactiveUser_Returns401(UserStatus status)
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var email = NewEmail();
        var userId = await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);
        await SetStatusAsync(app.Services, userId, status);

        using var response = await GetProtectedAsync(client, $"access_token={CookieValue(login, "access_token")}");

        await AssertInvalidSessionAsync(response);
    }
```

- [ ] **Step 3: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~SessionTests.Access"`
Expected: FAIL — no authentication scheme is registered (`InvalidOperationException: No authenticationScheme was specified`).

- [ ] **Step 4: Implement the handler**

```csharp
using System.Security.Claims;
using System.Text.Encodings.Web;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Authentication;
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
```

- [ ] **Step 5: Register authentication in `Program.cs`**

After `builder.Services.AddScoped<LoginService>();`:

```csharp
builder.Services.AddAuthentication(AccessCookieAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, AccessCookieAuthenticationHandler>(AccessCookieAuthenticationHandler.SchemeName, null);
builder.Services.AddAuthorization();
```

Add `using Microsoft.AspNetCore.Authentication;`. In the pipeline, after `app.UseRateLimiter();`:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

- [ ] **Step 6: Run all tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src tests
git commit -m "feat: access cookie authentication handler"
```

### Task 8: `login_challenges` table and sign-in email port

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/LoginChallenge.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/AppDbContext.cs`
- Generate: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Migrations/*_LoginChallenges.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/ILoginEmailSender.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/SmtpEmailSender.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/IEmailSender.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MigrationTests.cs`

- [ ] **Step 1: Write the failing migration test**

Append to `MigrationTests` (add `using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;`, `using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;`, `using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;`):

```csharp
    [Fact]
    public async Task LoginChallenges_AllowOnlyOneUnconsumedAttemptPerUser()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = $"migration-{Guid.NewGuid():N}@example.com",
            PasswordHash = "hash",
            Status = UserStatus.Active,
            CreatedAt = now,
            UpdatedAt = now
        };
        LoginChallenge Challenge(DateTimeOffset? consumedAt) => new()
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Method = ChallengeMethod.Otp,
            SecretHash = "hash",
            LastSentAt = now,
            CreatedAt = now,
            ConsumedAt = consumedAt,
            ConsumedReason = consumedAt is null ? null : ConsumedReason.Replaced
        };
        db.Users.Add(user);
        db.LoginChallenges.AddRange(Challenge(now), Challenge(now), Challenge(null));
        await db.SaveChangesAsync();

        db.LoginChallenges.Add(Challenge(null));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~MigrationTests"`
Expected: build FAIL, `LoginChallenge` does not exist.

- [ ] **Step 3: Create the entity**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// no expires_at column: expiry is last_sent_at + 10 minutes (keeps the table in BCNF)
public class LoginChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public ChallengeMethod Method { get; set; }

    public string SecretHash { get; set; } = string.Empty;

    public DateTimeOffset LastSentAt { get; set; }

    public int Attempts { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public ConsumedReason? ConsumedReason { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

public enum ConsumedReason
{
    Confirmed,
    Replaced,
    AttemptsExhausted,
    UserInactive
}
```

- [ ] **Step 4: Map it in `AppDbContext`**

Add `using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;`. Add the set:

```csharp
    public DbSet<LoginChallenge> LoginChallenges => Set<LoginChallenge>();
```

At the end of `OnModelCreating`:

```csharp
        modelBuilder.Entity<LoginChallenge>(entity =>
        {
            entity.ToTable("login_challenges");
            entity.Property(challenge => challenge.Id).HasColumnName("id");
            entity.Property(challenge => challenge.UserId).HasColumnName("user_id");
            entity.Property(challenge => challenge.Method).HasColumnName("method").HasConversion<string>();
            entity.Property(challenge => challenge.SecretHash).HasColumnName("secret_hash");
            entity.Property(challenge => challenge.LastSentAt).HasColumnName("last_sent_at");
            entity.Property(challenge => challenge.Attempts).HasColumnName("attempts");
            entity.Property(challenge => challenge.ConsumedAt).HasColumnName("consumed_at");
            entity.Property(challenge => challenge.ConsumedReason).HasColumnName("consumed_reason").HasConversion<string>();
            entity.Property(challenge => challenge.CreatedAt).HasColumnName("created_at");
            entity.HasIndex(challenge => challenge.UserId)
                .IsUnique()
                .HasFilter("\"consumed_at\" IS NULL");
            entity.HasOne<User>().WithMany().HasForeignKey(challenge => challenge.UserId).OnDelete(DeleteBehavior.Cascade);
        });
```

- [ ] **Step 5: Generate the migration**

```bash
dotnet ef migrations add LoginChallenges \
  --project src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure \
  --startup-project src/FEDept.BackendCourse.GroupA1.Api.Template
```

Expected: `Migrations/<timestamp>_LoginChallenges.cs` with `CreateTable(name: "login_challenges")`, an index `IX_login_challenges_user_id` with `unique: true, filter: "\"consumed_at\" IS NULL"`, and a cascade FK to `Users`. Open it and check those three things; the migration must not touch `Users` or `registration_challenges`.

- [ ] **Step 6: Run the migration test**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~MigrationTests"`
Expected: PASS.

- [ ] **Step 7: Create `ILoginEmailSender`**

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public interface ILoginEmailSender
{
    Task SendLoginOtpAsync(string email, string code, CancellationToken ct);

    Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct);
}
```

- [ ] **Step 8: Implement it in `SmtpEmailSender` and `NullEmailSender`**

`SmtpEmailSender`: change the declaration to `public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailSender, ILoginEmailSender`, add `using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;`, and insert after `SendMagicLinkAsync`:

```csharp
    public Task SendLoginOtpAsync(string email, string code, CancellationToken ct) =>
        SendAsync(email, "Sign-in code", $"Your sign-in code is {code}. It expires in 10 minutes.", ct);

    public Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct) =>
        SendAsync(email, "Confirm your sign-in", $"Open this link to finish signing in. It expires in 10 minutes: {link}", ct);
```

`NullEmailSender` in `IEmailSender.cs`: change to `public sealed class NullEmailSender : IEmailSender, ILoginEmailSender`, add the same using, and add:

```csharp
    public Task SendLoginOtpAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;

    public Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct) => Task.CompletedTask;
```

- [ ] **Step 9: Register one SMTP instance for both ports**

In `Program.cs`, replace `builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();` with:

```csharp
builder.Services.AddSingleton<SmtpEmailSender>();
builder.Services.AddSingleton<IEmailSender>(services => services.GetRequiredService<SmtpEmailSender>());
builder.Services.AddSingleton<ILoginEmailSender>(services => services.GetRequiredService<SmtpEmailSender>());
```

Existing tests replace `IEmailSender` with `RemoveAll<IEmailSender>()`; that still works.

- [ ] **Step 10: Run all tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS.

- [ ] **Step 11: Commit**

```bash
git add src tests
git commit -m "feat: login_challenges table and sign-in email sender"
```

### Task 9: Email challenge — service, contracts, endpoints, OTP tests

**Files:**
- Modify (full rewrite): `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Authentication/LoginService.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/LoginChallengeResponse.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/LoginConfirmRequest.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/LoginResendRequest.cs`
- Modify (full rewrite): `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/LoginController.cs`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/AuthTestKit.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/OtpChallengeTests.cs`

- [ ] **Step 1: Extend the test kit**

Add these usings to `AuthTestKit.cs`: `System.Collections.Concurrent`, `FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication`, `Microsoft.Extensions.DependencyInjection.Extensions`, `Microsoft.Extensions.Options`. Add to the `AuthTestKit` class:

```csharp
    public static WebApplicationFactory<Program> WithChallenge(
        this RegistrationTestFactory factory, string method, CapturingLoginEmailSender sender) =>
        factory.WithSettings(
            new Dictionary<string, string?>
            {
                ["Login:ConfirmationEnabled"] = "true",
                ["Login:ConfirmationMethod"] = method
            },
            services =>
            {
                services.RemoveAll<ILoginEmailSender>();
                services.AddSingleton<ILoginEmailSender>(sender);
            });

    public static async Task<LoginChallenge> GetChallengeAsync(IServiceProvider services, Guid attemptId)
    {
        using var scope = services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AppDbContext>().LoginChallenges
            .AsNoTracking()
            .SingleAsync(challenge => challenge.Id == attemptId);
    }

    // moves the send time back instead of waiting for the 60 s pause or the 10 min TTL
    public static async Task AgeChallengeAsync(IServiceProvider services, Guid attemptId, TimeSpan by)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var challenge = await db.LoginChallenges.SingleAsync(item => item.Id == attemptId);
        challenge.LastSentAt -= by;
        await db.SaveChangesAsync();
    }

    public static string ChallengeHash(IServiceProvider services, string secret) =>
        new SecretHasher(services.GetRequiredService<IOptions<LoginOptions>>().Value.ChallengeHmacKey).Hash(secret);
```

Add a new class in the same file:

```csharp
public sealed class CapturingLoginEmailSender : ILoginEmailSender
{
    public ConcurrentQueue<(string Email, string Secret)> Sent { get; } = new();

    public bool Fail { get; set; }

    public Task SendLoginOtpAsync(string email, string code, CancellationToken ct) => Capture(email, code);

    public Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct) => Capture(email, link);

    public string LastFor(string email) => Sent.Last(item => item.Email == email).Secret;

    public int CountFor(string email) => Sent.Count(item => item.Email == email);

    private Task Capture(string email, string secret)
    {
        if (Fail)
        {
            throw new InvalidOperationException("SMTP rejected the message.");
        }

        Sent.Enqueue((email, secret));
        return Task.CompletedTask;
    }
}
```

- [ ] **Step 2: Write the failing OTP tests**

`Auth/OtpChallengeTests.cs`:

```csharp
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class OtpChallengeTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private readonly RegistrationTestFactory _factory;
    private readonly CapturingLoginEmailSender _sender = new();
    private readonly WebApplicationFactory<Program> _app;
    private readonly HttpClient _client;

    public OtpChallengeTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _app = factory.WithChallenge("Otp", _sender);
        _client = CreateClient(_app);
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    private async Task<(string Email, Guid UserId, Guid AttemptId)> StartAsync()
    {
        var email = NewEmail();
        var userId = await CreateUserAsync(_app.Services, email);
        using var login = await LoginAsync(_client, email);
        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        return (email, userId, body.GetProperty("attemptId").GetGuid());
    }

    private Task<HttpResponseMessage> ConfirmAsync(Guid attemptId, string code) =>
        _client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code });

    private Task<HttpResponseMessage> ResendAsync(Guid attemptId) =>
        _client.PostAsJsonAsync("/auth/login/resend", new { attemptId });

    private static string WrongCode(string code) => code == "000000" ? "111111" : "000000";

    [Fact]
    public async Task Login_ReturnsAcceptedWithoutSecretOrCookies()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email);

        using var login = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        Assert.Empty(SetCookies(login));
        var json = await login.Content.ReadAsStringAsync();
        var body = JsonDocument.Parse(json).RootElement;
        Assert.True(body.GetProperty("confirmationRequired").GetBoolean());
        Assert.Equal("otp", body.GetProperty("method").GetString());
        Assert.Equal(600, body.GetProperty("expiresInSeconds").GetInt32());
        Assert.Equal(60, body.GetProperty("resendAfterSeconds").GetInt32());
        var code = _sender.LastFor(email);
        Assert.Matches("^[0-9]{6}$", code);
        Assert.DoesNotContain(code, json, StringComparison.Ordinal);
        var challenge = await GetChallengeAsync(_app.Services, body.GetProperty("attemptId").GetGuid());
        Assert.Equal(ChallengeHash(_app.Services, code), challenge.SecretHash);
        Assert.Null(challenge.ConsumedAt);
    }

    [Fact]
    public async Task Login_InactiveUser_Returns401WithoutEmail()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email, UserStatus.Blocked);

        using var login = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Equal(0, _sender.CountFor(email));
    }

    [Fact]
    public async Task Confirm_CorrectCode_SetsCookiesAndConsumesAttempt()
    {
        var (email, _, attemptId) = await StartAsync();

        using var response = await ConfirmAsync(attemptId, _sender.LastFor(email));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        AssertSessionCookies(response);
        Assert.Equal(ConsumedReason.Confirmed, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
        using var again = await ConfirmAsync(attemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
    }

    [Fact]
    public async Task Confirm_FifthWrongCodeConsumes_NextEntryReturns429()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);
        for (var i = 1; i <= 5; i++)
        {
            using var wrong = await ConfirmAsync(attemptId, WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(5, challenge.Attempts);
        Assert.Equal(ConsumedReason.AttemptsExhausted, challenge.ConsumedReason);
        using var next = await ConfirmAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.TooManyRequests, next.StatusCode);
    }

    [Fact]
    public async Task Confirm_CorrectFifthEntry_Succeeds()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);
        for (var i = 1; i <= 4; i++)
        {
            using var wrong = await ConfirmAsync(attemptId, WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        using var fifth = await ConfirmAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.NoContent, fifth.StatusCode);
    }

    [Fact]
    public async Task Confirm_Expired_Returns400WithoutCountingTheEntry()
    {
        var (email, _, attemptId) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromMinutes(10));

        using var response = await ConfirmAsync(attemptId, _sender.LastFor(email));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, (await GetChallengeAsync(_app.Services, attemptId)).Attempts);
    }

    [Fact]
    public async Task Confirm_UnknownAttempt_Returns400()
    {
        using var response = await ConfirmAsync(Guid.NewGuid(), "123456");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"12345\"}")]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"abcdef\"}")]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"١٢٣٤٥٦\"}")]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"123456\\n\"}")]
    [InlineData("{\"code\":\"123456\"}")]
    [InlineData("{\"token\":\"short\"}")]
    [InlineData("{}")]
    public async Task Confirm_InvalidFormat_Returns400(string json)
    {
        using var response = await _client.PostAsync("/auth/login/confirm", new StringContent(json, System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Confirm_UserBlockedMidChallenge_Returns401AndConsumesAsUserInactive()
    {
        var (email, userId, attemptId) = await StartAsync();
        await SetStatusAsync(_app.Services, userId, UserStatus.Blocked);

        using var response = await ConfirmAsync(attemptId, _sender.LastFor(email));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_credentials", body.GetProperty("code").GetString());
        Assert.Equal(ConsumedReason.UserInactive, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
        using var resend = await ResendAsync(attemptId);
        Assert.Equal(HttpStatusCode.BadRequest, resend.StatusCode);
    }

    [Fact]
    public async Task Login_WithinPause_Returns429WithoutNewEmail()
    {
        var (email, _, _) = await StartAsync();

        using var second = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        var body = await second.Content.ReadFromJsonAsync<JsonElement>();
        Assert.InRange(body.GetProperty("retryAfterSeconds").GetInt32(), 1, 60);
        Assert.Equal(1, _sender.CountFor(email));
    }

    [Fact]
    public async Task Login_AfterPause_ReplacesPreviousAttempt()
    {
        var (email, _, oldAttemptId) = await StartAsync();
        var oldCode = _sender.LastFor(email);
        await AgeChallengeAsync(_app.Services, oldAttemptId, TimeSpan.FromSeconds(61));

        using var second = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        var newAttemptId = (await second.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("attemptId").GetGuid();
        Assert.NotEqual(oldAttemptId, newAttemptId);
        Assert.Equal(ConsumedReason.Replaced, (await GetChallengeAsync(_app.Services, oldAttemptId)).ConsumedReason);
        using var old = await ConfirmAsync(oldAttemptId, oldCode);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var fresh = await ConfirmAsync(newAttemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }

    [Fact]
    public async Task Resend_WithinPause_Returns429()
    {
        var (_, _, attemptId) = await StartAsync();

        using var response = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(response.Headers.RetryAfter is not null);
    }

    [Fact]
    public async Task Resend_AfterPause_ReplacesSecretAndResetsAttempts()
    {
        var (email, _, attemptId) = await StartAsync();
        var oldCode = _sender.LastFor(email);
        using (var wrong = await ConfirmAsync(attemptId, WrongCode(oldCode)))
        {
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        var body = await resend.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("otp", body.GetProperty("method").GetString());
        Assert.Equal(attemptId, body.GetProperty("attemptId").GetGuid());
        Assert.Equal(600, body.GetProperty("expiresInSeconds").GetInt32());
        Assert.Equal(60, body.GetProperty("resendAfterSeconds").GetInt32());
        var newCode = _sender.LastFor(email);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(0, challenge.Attempts);
        Assert.Equal(ChallengeHash(_app.Services, newCode), challenge.SecretHash);
        if (newCode != oldCode)
        {
            using var old = await ConfirmAsync(attemptId, oldCode);
            Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        }

        using var fresh = await ConfirmAsync(attemptId, newCode);
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }

    [Fact]
    public async Task Resend_AfterExpiry_IsAllowed()
    {
        var (email, _, attemptId) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromMinutes(11));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        using var confirm = await ConfirmAsync(attemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_ExhaustedAttempt_Returns429()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);
        for (var i = 0; i < 5; i++)
        {
            using var wrong = await ConfirmAsync(attemptId, WrongCode(code));
        }

        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.TooManyRequests, resend.StatusCode);
    }

    [Fact]
    public async Task Resend_UnknownOrConfirmedAttempt_Returns400()
    {
        var (email, _, attemptId) = await StartAsync();
        using (var confirm = await ConfirmAsync(attemptId, _sender.LastFor(email)))
        {
            Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
        }

        using var confirmed = await ResendAsync(attemptId);
        using var unknown = await ResendAsync(Guid.NewGuid());

        Assert.Equal(HttpStatusCode.BadRequest, confirmed.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
    }

    [Fact]
    public async Task Resend_KeepsTheStoredMethodAfterConfigurationChanges()
    {
        var (email, _, attemptId) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));
        var linkSender = new CapturingLoginEmailSender();
        using var magicLinkApp = _factory.WithChallenge("MagicLink", linkSender);
        using var magicLinkClient = CreateClient(magicLinkApp);

        using var resend = await magicLinkClient.PostAsJsonAsync("/auth/login/resend", new { attemptId });

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal("otp", (await resend.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("method").GetString());
        Assert.Matches("^[0-9]{6}$", linkSender.LastFor(email));
    }

    [Fact]
    public async Task Login_SmtpFailure_Returns503WithAttemptAndKeepsIt()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email);
        _sender.Fail = true;

        using var login = await LoginAsync(_client, email);

        _sender.Fail = false;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("confirmationRequired").GetBoolean());
        Assert.Equal("otp", body.GetProperty("method").GetString());
        Assert.Equal(60, body.GetProperty("retryAfterSeconds").GetInt32());
        var attemptId = body.GetProperty("attemptId").GetGuid();
        Assert.Null((await GetChallengeAsync(_app.Services, attemptId)).ConsumedAt);
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));
        using var resend = await ResendAsync(attemptId);
        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        using var confirm = await ConfirmAsync(attemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_SmtpFailure_Returns503AndKeepsTheNewHash()
    {
        var (_, _, attemptId) = await StartAsync();
        var oldHash = (await GetChallengeAsync(_app.Services, attemptId)).SecretHash;
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));
        _sender.Fail = true;

        using var resend = await ResendAsync(attemptId);

        _sender.Fail = false;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resend.StatusCode);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.NotEqual(oldHash, challenge.SecretHash);
        Assert.True(DateTimeOffset.UtcNow - challenge.LastSentAt < TimeSpan.FromSeconds(60));
    }
}
```

`Resend_AfterPause_ReplacesSecretAndResetsAttempts` guards the old-code check with `newCode != oldCode`: a random six-digit code repeats one time in a million.

- [ ] **Step 3: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~OtpChallengeTests"`
Expected: FAIL — login returns 204 instead of 202, and confirm/resend return 404.

- [ ] **Step 4: Create the challenge contracts**

`Contracts/LoginChallengeResponse.cs`:

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record LoginChallengeResponse(
    bool ConfirmationRequired,
    string Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds);

// 503 after the attempt was committed but SMTP refused the email; never carries the secret
public sealed record LoginChallengeFailedResponse(
    bool ConfirmationRequired,
    string Method,
    Guid AttemptId,
    int RetryAfterSeconds);

public sealed record LoginResendResponse(
    string Method,
    Guid AttemptId,
    int ExpiresInSeconds,
    int ResendAfterSeconds);
```

`Contracts/LoginConfirmRequest.cs`:

```csharp
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed partial record LoginConfirmRequest(Guid? AttemptId, string? Code, string? Token) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!TryParse(out _, out _, out _))
        {
            yield return new ValidationResult(
                "Provide either attemptId and a 6-digit code, or token.",
                [nameof(AttemptId), nameof(Code), nameof(Token)]);
        }
    }

    // token is "{attemptId}.{secret}": a 36-char Guid and 32 random bytes in base64url (43 chars)
    public bool TryParse(out Guid attemptId, out ChallengeMethod method, out string secret)
    {
        if (AttemptId is { } id && Token is null && Code is not null && OtpCode().IsMatch(Code))
        {
            (attemptId, method, secret) = (id, ChallengeMethod.Otp, Code);
            return true;
        }

        if (AttemptId is null && Code is null && Token is not null && LinkToken().IsMatch(Token)
            && Guid.TryParseExact(Token[..36], "D", out var tokenId))
        {
            (attemptId, method, secret) = (tokenId, ChallengeMethod.MagicLink, Token[37..]);
            return true;
        }

        (attemptId, method, secret) = (Guid.Empty, ChallengeMethod.Otp, string.Empty);
        return false;
    }

    [GeneratedRegex(@"^[0-9]{6}\z")]
    private static partial Regex OtpCode();

    [GeneratedRegex(@"^[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{43}\z")]
    private static partial Regex LinkToken();
}
```

`[0-9]` rather than `\d` (which also matches non-ASCII digits) and `\z` rather than `$` (which allows a trailing newline).

`Contracts/LoginResendRequest.cs`:

```csharp
using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record LoginResendRequest([Required] Guid? AttemptId);
```

- [ ] **Step 5: Rewrite `LoginService` with the challenge flow**

Replace the whole file:

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class LoginService(
    AppDbContext db,
    IOptionsSnapshot<LoginOptions> options,
    JwtTokenService tokens,
    FailedLoginLimiter failedLogins,
    ILoginEmailSender emailSender,
    AuthAudit audit)
{
    public const int MaxOtpAttempts = 5;
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan ResendPause = TimeSpan.FromSeconds(60);

    // prepared once; a missing account still costs one BCrypt check
    private static readonly string DummyHash = PasswordHasher.Hash(Guid.NewGuid().ToString());

    private SecretHasher Hasher => new(options.Value.ChallengeHmacKey);

    public async Task<LoginResult> LoginAsync(string email, string password, string clientIp, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        var emailRef = audit.EmailRef(normalizedEmail);
        // reserves a failure slot before BCrypt, so concurrent guesses cannot exceed the limit
        if (failedLogins.TryBeginAttempt(emailRef, clientIp) is { } wait)
        {
            audit.Login(null, emailRef, "rate_limited_pair");
            return new LoginResult.TooManyRequests(wait);
        }

        User? user;
        bool valid;
        try
        {
            user = await db.Users.AsNoTracking().SingleOrDefaultAsync(item => item.Email == normalizedEmail, ct);
            valid = PasswordHasher.Verify(password, user?.PasswordHash ?? DummyHash) && user is { Status: UserStatus.Active };
        }
        catch
        {
            // an outage is not a failed check
            failedLogins.Release(emailRef, clientIp);
            throw;
        }

        if (!valid || user is null)
        {
            // the reserved slot stays as the recorded failure
            audit.Login(user?.Id, emailRef, "invalid_credentials");
            return LoginResult.InvalidCredentials.Instance;
        }

        failedLogins.Release(emailRef, clientIp);

        if (!options.Value.ConfirmationEnabled)
        {
            var pair = tokens.Issue(user.Id);
            audit.Login(user.Id, null, "success");
            return new LoginResult.SignedIn(pair);
        }

        return await StartChallengeAsync(user.Id, ct);
    }

    public async Task<TokenPair?> RefreshAsync(string? refreshToken, CancellationToken ct)
    {
        var validation = await tokens.ValidateAsync(refreshToken, TokenUse.Refresh);
        if (validation is TokenValidation.Fail fail)
        {
            audit.Refresh(null, "failure", fail.Category);
            return null;
        }

        var userId = ((TokenValidation.Ok)validation).UserId;
        if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == userId && user.Status == UserStatus.Active, ct))
        {
            audit.Refresh(userId, "failure", "user_inactive");
            return null;
        }

        // stateless: the used refresh token is not stored or denylisted
        var pair = tokens.Issue(userId);
        audit.Refresh(userId, "success", null);
        return pair;
    }

    public async Task<LoginConfirmResult> ConfirmAsync(Guid attemptId, ChallengeMethod method, string secret, CancellationToken ct)
    {
        var userId = await FindUserIdAsync(attemptId, ct);
        if (userId is null)
        {
            audit.Challenge(null, attemptId, method, "rejected");
            return LoginConfirmResult.Invalid.Instance;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var (user, challenge) = await LockAsync(userId.Value, attemptId, ct);
        if (challenge?.ConsumedReason == ConsumedReason.AttemptsExhausted)
        {
            audit.Challenge(userId, attemptId, challenge.Method, "exhausted");
            return LoginConfirmResult.Exhausted.Instance;
        }

        if (challenge is null || challenge.ConsumedAt is not null || challenge.Method != method)
        {
            audit.Challenge(userId, attemptId, method, "rejected");
            return LoginConfirmResult.Invalid.Instance;
        }

        var now = DateTimeOffset.UtcNow;
        if (challenge.LastSentAt + ChallengeLifetime <= now)
        {
            audit.Challenge(userId, attemptId, method, "expired");
            return LoginConfirmResult.Invalid.Instance;
        }

        if (user is not { Status: UserStatus.Active })
        {
            await ConsumeAsync(challenge, ConsumedReason.UserInactive, now, transaction, ct);
            audit.Challenge(userId, attemptId, method, "user_inactive");
            return LoginConfirmResult.InvalidCredentials.Instance;
        }

        if (!Hasher.Matches(secret, challenge.SecretHash))
        {
            if (method == ChallengeMethod.Otp)
            {
                // the fifth entry is still checked; a fifth miss consumes the attempt
                challenge.Attempts++;
                if (challenge.Attempts >= MaxOtpAttempts)
                {
                    challenge.ConsumedAt = now;
                    challenge.ConsumedReason = ConsumedReason.AttemptsExhausted;
                }

                await db.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
            }

            audit.Challenge(userId, attemptId, method, challenge.ConsumedAt is null ? "wrong_entry" : "exhausted");
            return LoginConfirmResult.Invalid.Instance;
        }

        // sign before commit: a signing failure rolls back and the attempt stays confirmable
        var pair = tokens.Issue(user.Id);
        await ConsumeAsync(challenge, ConsumedReason.Confirmed, now, transaction, ct);
        audit.Challenge(userId, attemptId, method, "confirmed");
        return new LoginConfirmResult.SignedIn(pair);
    }

    public async Task<LoginResendResult> ResendAsync(Guid attemptId, CancellationToken ct)
    {
        var userId = await FindUserIdAsync(attemptId, ct);
        if (userId is null)
        {
            audit.Challenge(null, attemptId, null, "rejected");
            return LoginResendResult.Invalid.Instance;
        }

        LoginChallenge? challenge;
        string secret;
        string email;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            (var user, challenge) = await LockAsync(userId.Value, attemptId, ct);
            if (challenge?.ConsumedReason == ConsumedReason.AttemptsExhausted)
            {
                audit.Challenge(userId, attemptId, challenge.Method, "exhausted");
                return LoginResendResult.Exhausted.Instance;
            }

            if (challenge is null || challenge.ConsumedAt is not null)
            {
                audit.Challenge(userId, attemptId, challenge?.Method, "rejected");
                return LoginResendResult.Invalid.Instance;
            }

            var now = DateTimeOffset.UtcNow;
            if (user is not { Status: UserStatus.Active })
            {
                await ConsumeAsync(challenge, ConsumedReason.UserInactive, now, transaction, ct);
                audit.Challenge(userId, attemptId, challenge.Method, "user_inactive");
                return LoginResendResult.InvalidCredentials.Instance;
            }

            if (RetryAfter(challenge.LastSentAt, now) is { } wait)
            {
                audit.Challenge(userId, attemptId, challenge.Method, "cooldown");
                return new LoginResendResult.TooSoon(wait);
            }

            // an expired TTL does not block resend; the new send restarts it
            secret = GenerateSecret(challenge.Method);
            challenge.SecretHash = Hasher.Hash(secret);
            challenge.LastSentAt = now;
            challenge.Attempts = 0;
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            email = user.Email;
        }

        audit.Challenge(userId, attemptId, challenge.Method, "resent");
        // on SMTP failure the new hash stays; the old secret is not restored
        return await TrySendAsync(email, challenge, secret, ct)
            ? new LoginResendResult.Sent(challenge.Id, challenge.Method)
            : new LoginResendResult.NotSent(challenge.Id, challenge.Method);
    }

    private async Task<LoginResult> StartChallengeAsync(Guid userId, CancellationToken ct)
    {
        var lastSentAt = await db.LoginChallenges.AsNoTracking()
            .Where(challenge => challenge.UserId == userId && challenge.ConsumedAt == null)
            .Select(challenge => (DateTimeOffset?)challenge.LastSentAt)
            .SingleOrDefaultAsync(ct);
        if (RetryAfter(lastSentAt, DateTimeOffset.UtcNow) is { } wait)
        {
            audit.Login(userId, null, "cooldown");
            return new LoginResult.TooManyRequests(wait);
        }

        var method = options.Value.ConfirmationMethod;
        var secret = GenerateSecret(method);
        LoginChallenge challenge;
        string email;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            // lock order is user, then challenge, everywhere
            var user = await LockUserAsync(userId, ct);
            if (user is not { Status: UserStatus.Active })
            {
                audit.Login(userId, null, "invalid_credentials");
                return LoginResult.InvalidCredentials.Instance;
            }

            var previous = await db.LoginChallenges
                .FromSqlInterpolated($"SELECT * FROM login_challenges WHERE user_id = {userId} AND consumed_at IS NULL FOR UPDATE")
                .SingleOrDefaultAsync(ct);
            var now = DateTimeOffset.UtcNow;
            if (RetryAfter(previous?.LastSentAt, now) is { } lockedWait)
            {
                audit.Login(userId, null, "cooldown");
                return new LoginResult.TooManyRequests(lockedWait);
            }

            if (previous is not null)
            {
                previous.ConsumedAt = now;
                previous.ConsumedReason = ConsumedReason.Replaced;
                // separate save frees the partial unique index before the insert
                await db.SaveChangesAsync(ct);
            }

            challenge = new LoginChallenge
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Method = method,
                SecretHash = Hasher.Hash(secret),
                LastSentAt = now,
                Attempts = 0,
                CreatedAt = now
            };
            db.LoginChallenges.Add(challenge);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            email = user.Email;
        }

        audit.Challenge(userId, challenge.Id, method, "created");
        return await TrySendAsync(email, challenge, secret, ct)
            ? new LoginResult.ChallengeSent(challenge.Id, method)
            : new LoginResult.ChallengeNotSent(challenge.Id, method, (int)ResendPause.TotalSeconds);
    }

    private Task<Guid?> FindUserIdAsync(Guid attemptId, CancellationToken ct) =>
        db.LoginChallenges.AsNoTracking()
            .Where(challenge => challenge.Id == attemptId)
            .Select(challenge => (Guid?)challenge.UserId)
            .SingleOrDefaultAsync(ct);

    private Task<User?> LockUserAsync(Guid userId, CancellationToken ct) =>
        db.Users.FromSqlInterpolated($"SELECT * FROM \"Users\" WHERE \"Id\" = {userId} FOR UPDATE").SingleOrDefaultAsync(ct);

    private async Task<(User? User, LoginChallenge? Challenge)> LockAsync(Guid userId, Guid attemptId, CancellationToken ct)
    {
        var user = await LockUserAsync(userId, ct);
        var challenge = await db.LoginChallenges
            .FromSqlInterpolated($"SELECT * FROM login_challenges WHERE id = {attemptId} FOR UPDATE")
            .SingleOrDefaultAsync(ct);
        return (user, challenge);
    }

    private async Task ConsumeAsync(
        LoginChallenge challenge, ConsumedReason reason, DateTimeOffset now, IDbContextTransaction transaction, CancellationToken ct)
    {
        challenge.ConsumedAt = now;
        challenge.ConsumedReason = reason;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
    }

    private static int? RetryAfter(DateTimeOffset? lastSentAt, DateTimeOffset now)
    {
        var remaining = lastSentAt + ResendPause - now;
        return remaining > TimeSpan.Zero ? (int)Math.Ceiling(remaining.Value.TotalSeconds) : null;
    }

    private static string GenerateSecret(ChallengeMethod method) =>
        method == ChallengeMethod.MagicLink ? MagicLinkTokenGenerator.Generate() : OtpGenerator.Generate();

    private async Task<bool> TrySendAsync(string email, LoginChallenge challenge, string secret, CancellationToken ct)
    {
        try
        {
            if (challenge.Method == ChallengeMethod.MagicLink)
            {
                // the fragment never reaches the server or Referer; the page POSTs it to /auth/login/confirm
                await emailSender.SendLoginMagicLinkAsync(email, $"{options.Value.MagicLinkBaseUrl}#token={challenge.Id}.{secret}", ct);
            }
            else
            {
                await emailSender.SendLoginOtpAsync(email, secret, ct);
            }

            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            audit.Challenge(challenge.UserId, challenge.Id, challenge.Method, "send_failed");
            audit.DependencyUnavailable("smtp");
            return false;
        }
    }
}

public abstract record LoginResult
{
    public sealed record SignedIn(TokenPair Tokens) : LoginResult;

    public sealed record ChallengeSent(Guid AttemptId, ChallengeMethod Method) : LoginResult;

    public sealed record ChallengeNotSent(Guid AttemptId, ChallengeMethod Method, int RetryAfterSeconds) : LoginResult;

    public sealed record InvalidCredentials : LoginResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }

    public sealed record TooManyRequests(int RetryAfterSeconds) : LoginResult;
}

public abstract record LoginConfirmResult
{
    public sealed record SignedIn(TokenPair Tokens) : LoginConfirmResult;

    public sealed record Invalid : LoginConfirmResult
    {
        public static Invalid Instance { get; } = new();
    }

    public sealed record Exhausted : LoginConfirmResult
    {
        public static Exhausted Instance { get; } = new();
    }

    public sealed record InvalidCredentials : LoginConfirmResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }
}

public abstract record LoginResendResult
{
    public sealed record Sent(Guid AttemptId, ChallengeMethod Method) : LoginResendResult;

    public sealed record NotSent(Guid AttemptId, ChallengeMethod Method) : LoginResendResult;

    public sealed record TooSoon(int RetryAfterSeconds) : LoginResendResult;

    public sealed record Invalid : LoginResendResult
    {
        public static Invalid Instance { get; } = new();
    }

    public sealed record Exhausted : LoginResendResult
    {
        public static Exhausted Instance { get; } = new();
    }

    public sealed record InvalidCredentials : LoginResendResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }
}
```

Two rules this code relies on:
- The first reads use `AsNoTracking` or projections. A later `FromSql … FOR UPDATE` must load fresh rows; a tracked instance would keep stale values.
- Returning from inside a transaction block before `CommitAsync` disposes the transaction, which rolls it back.

- [ ] **Step 6: Rewrite `LoginController`**

Replace the whole file:

```csharp
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
```

- [ ] **Step 7: Run the challenge and existing tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS. Direct-login tests still pass because the factory leaves `Login:ConfirmationEnabled` false.

- [ ] **Step 8: Commit**

```bash
git add src tests
git commit -m "feat: login email challenge with OTP confirm and resend"
```

### Task 10: Magic-link tests

The code from Task 9 already supports the magic link. This task proves it.

**Files:**
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/MagicLinkChallengeTests.cs`

- [ ] **Step 1: Write the tests**

```csharp
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class MagicLinkChallengeTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private const string BaseUrl = "https://app.example.test/login/confirm";
    private readonly CapturingLoginEmailSender _sender = new();
    private readonly WebApplicationFactory<Program> _app;
    private readonly HttpClient _client;

    public MagicLinkChallengeTests(RegistrationTestFactory factory)
    {
        _app = factory.WithChallenge("MagicLink", _sender);
        _client = CreateClient(_app);
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    private async Task<(string Email, Guid AttemptId, string Token)> StartAsync()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email);
        using var login = await LoginAsync(_client, email);
        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("magic_link", body.GetProperty("method").GetString());
        var link = _sender.LastFor(email);
        return (email, body.GetProperty("attemptId").GetGuid(), link[(link.IndexOf("#token=", StringComparison.Ordinal) + 7)..]);
    }

    private Task<HttpResponseMessage> ConfirmAsync(string token) =>
        _client.PostAsJsonAsync("/auth/login/confirm", new { token });

    [Fact]
    public async Task Login_SendsLinkWithTokenInFragmentOnly()
    {
        var (email, attemptId, token) = await StartAsync();

        var link = _sender.LastFor(email);

        Assert.StartsWith($"{BaseUrl}#token=", link, StringComparison.Ordinal);
        Assert.DoesNotContain("?", link, StringComparison.Ordinal);
        Assert.Matches($"^{attemptId}\\.[A-Za-z0-9_-]{{43}}$", token);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(ChallengeHash(_app.Services, token[37..]), challenge.SecretHash);
    }

    [Fact]
    public async Task Confirm_ValidToken_SetsCookies()
    {
        var (_, attemptId, token) = await StartAsync();

        using var response = await ConfirmAsync(token);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        AssertSessionCookies(response);
        Assert.Equal(ConsumedReason.Confirmed, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
    }

    [Fact]
    public async Task Confirm_WrongSecret_Returns400WithoutCounting()
    {
        var (_, attemptId, token) = await StartAsync();
        var wrong = $"{attemptId}.{new string('A', 43)}";

        for (var i = 0; i < 6; i++)
        {
            using var response = await ConfirmAsync(wrong);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        Assert.Equal(0, (await GetChallengeAsync(_app.Services, attemptId)).Attempts);
        using var valid = await ConfirmAsync(token);
        Assert.Equal(HttpStatusCode.NoContent, valid.StatusCode);
    }

    [Fact]
    public async Task Confirm_OtpShapeForLinkAttempt_Returns400()
    {
        var (_, attemptId, _) = await StartAsync();

        using var response = await _client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code = "123456" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11.tooShort")]
    [InlineData("5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Confirm_MalformedToken_Returns400(string token)
    {
        using var response = await ConfirmAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Confirm_Expired_Returns400()
    {
        var (_, attemptId, token) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromMinutes(10));

        using var response = await ConfirmAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Resend_ReplacesLink_OldLinkStopsWorking()
    {
        var (email, attemptId, oldToken) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await _client.PostAsJsonAsync("/auth/login/resend", new { attemptId });

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal("magic_link", (await resend.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("method").GetString());
        var link = _sender.LastFor(email);
        var newToken = link[(link.IndexOf("#token=", StringComparison.Ordinal) + 7)..];
        using var old = await ConfirmAsync(oldToken);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var fresh = await ConfirmAsync(newToken);
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }
}
```

- [ ] **Step 2: Run the tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~MagicLinkChallengeTests"`
Expected: PASS. A failure here is a defect in Task 9 code; fix it there, not in the test.

- [ ] **Step 3: Commit**

```bash
git add tests
git commit -m "test: magic link sign-in confirmation"
```

### Task 11: CSRF, CORS and the HTTPS guard

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/CsrfMiddleware.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Authentication/HttpsOnlyMiddleware.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/BrowserProtectionTests.cs`

- [ ] **Step 1: Write the failing tests**

```csharp
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class BrowserProtectionTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private const string Frontend = "https://app.example.test";

    private WebApplicationFactory<Program> WithFrontend(bool crossSite = false) =>
        factory.WithSettings(new Dictionary<string, string?>
        {
            ["Frontend:Origin"] = Frontend,
            ["Frontend:CrossSite"] = crossSite ? "true" : "false"
        });

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, string path, string? origin, bool csrfHeader = false, object? body = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = body is null ? null : JsonContent.Create(body) };
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }

        if (csrfHeader)
        {
            request.Headers.Add("X-CSRF-Protection", "1");
        }

        return client.SendAsync(request);
    }

    private static async Task AssertCsrfRejectedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("csrf_rejected", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://localhost")]
    public async Task Post_WithoutOriginOrFromOwnOrigin_Passes(string? origin)
    {
        using var client = CreateClient(factory);

        using var response = await PostAsync(client, "/auth/logout", origin);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Theory]
    [InlineData("/auth/logout")]
    [InlineData("/auth/refresh")]
    [InlineData("/auth/login")]
    [InlineData("/auth/register")]
    public async Task Post_FromForeignOrigin_Returns403(string path)
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, path, "https://evil.example", csrfHeader: true);

        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task Post_FromTrustedOriginWithoutHeader_Returns403()
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, "/auth/logout", Frontend);

        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task Post_FromTrustedOriginWithHeader_PassesWithCorsHeaders()
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, "/auth/logout", Frontend, csrfHeader: true);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(Frontend, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Credentials")));
    }

    [Fact]
    public async Task Preflight_TrustedOrigin_IsAllowed_ForeignOriginIsNot()
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        HttpRequestMessage Preflight(string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Options, "/auth/login");
            request.Headers.Add("Origin", origin);
            request.Headers.Add("Access-Control-Request-Method", "POST");
            request.Headers.Add("Access-Control-Request-Headers", "content-type,x-csrf-protection");
            return request;
        }

        using var trusted = await client.SendAsync(Preflight(Frontend));
        using var foreign = await client.SendAsync(Preflight("https://evil.example"));

        Assert.Equal(Frontend, Assert.Single(trusted.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(trusted.Headers.GetValues("Access-Control-Allow-Credentials")));
        Assert.False(foreign.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task CrossSiteFrontend_SwitchesCookiesToSameSiteNone()
    {
        using var app = WithFrontend(crossSite: true);
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);

        using var response = await PostAsync(client, "/auth/login", Frontend, csrfHeader: true, new { email, password = Password });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        AssertSessionCookies(response, sameSite: "none");
    }

    [Fact]
    public async Task PlainHttpOutsideDevelopment_Returns400HttpsRequired()
    {
        using var app = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
        using var client = CreateClient(app, "http://localhost");

        using var response = await client.PostAsJsonAsync("/auth/login", new { email = "user@example.com", password = "x" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("https_required", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~BrowserProtectionTests"`
Expected: FAIL — foreign origins are not rejected and no CORS headers are sent.

- [ ] **Step 3: Implement `CsrfMiddleware`**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

// browsers always send Origin on cross-origin POST; no Origin means a non-browser client
public sealed class CsrfMiddleware(RequestDelegate next, IOptions<FrontendOptions> frontend, AuthAudit audit)
{
    public const string HeaderName = "X-CSRF-Protection";

    public async Task InvokeAsync(HttpContext context)
    {
        if (HttpMethods.IsPost(context.Request.Method) && Rejection(context.Request) is { } reason)
        {
            audit.CsrfRejected(reason);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(ErrorResponses.CsrfRejected);
            return;
        }

        await next(context);
    }

    private string? Rejection(HttpRequest request)
    {
        var origin = request.Headers.Origin.ToString();
        if (origin.Length == 0 || string.Equals(origin, $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.Equals(origin, frontend.Value.Origin, StringComparison.Ordinal))
        {
            return "origin";
        }

        return request.Headers[HeaderName] == "1" ? null : "header";
    }
}
```

- [ ] **Step 4: Implement `HttpsOnlyMiddleware`**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

// rejects instead of redirecting, so a password sent over HTTP is not sent a second time
public sealed class HttpsOnlyMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.IsHttps && context.Request.Path.StartsWithSegments("/auth"))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(ErrorResponses.HttpsRequired);
            return;
        }

        await next(context);
    }
}
```

- [ ] **Step 5: Wire CORS and both middlewares in `Program.cs`**

Add `using Microsoft.AspNetCore.Cors.Infrastructure;`. After `builder.Services.AddAuthorization();`:

```csharp
builder.Services.AddCors();
// read lazily so configuration overrides (tests, reloads) apply
builder.Services.AddOptions<CorsOptions>().Configure<IOptions<FrontendOptions>>((cors, frontend) =>
{
    if (frontend.Value.Origin.Length > 0)
    {
        cors.AddDefaultPolicy(policy => policy
            .WithOrigins(frontend.Value.Origin)
            .AllowCredentials()
            .WithHeaders("Content-Type", CsrfMiddleware.HeaderName)
            .WithMethods("GET", "POST"));
    }
});
```

Change the forwarded headers to include the scheme, so `IsHttps` holds behind a TLS proxy:

```csharp
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
```

Right after `app.UseForwardedHeaders(...)`, before the `app.UseExceptionHandler(...)` call:

```csharp
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseMiddleware<HttpsOnlyMiddleware>();
}
```

Replace `app.UseRouting();` with:

```csharp
app.UseRouting();
app.UseCors();
app.UseMiddleware<CsrfMiddleware>();
```

The pipeline order is now: forwarded headers, HSTS + HTTPS guard (not in Development), exception handler, HTTPS redirection, routing, CORS, CSRF, rate limiter, authentication, authorization, controllers.

- [ ] **Step 6: Run all tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add src tests
git commit -m "feat: CSRF origin check, trusted-origin CORS and HTTPS guard"
```

### Task 12: Audit coverage and structured logs

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/AuthTestKit.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/AuthAuditTests.cs`

- [ ] **Step 1: Add a scope-aware log capture to the test kit**

Add usings `System.Text`, `Microsoft.Extensions.Logging`. Add the class:

```csharp
// IsEnabled is true for every category so the hosting RequestId scope is created; only AuthAudit lines are kept
public sealed class CapturingLoggerProvider : ILoggerProvider, ISupportExternalScope
{
    private IExternalScopeProvider _scopes = new LoggerExternalScopeProvider();

    public ConcurrentQueue<string> Messages { get; } = new();

    public ILogger CreateLogger(string categoryName) =>
        new CapturingLogger(this, categoryName == typeof(AuthAudit).FullName);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(CapturingLoggerProvider provider, bool capture) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => provider._scopes.Push(state);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!capture)
            {
                return;
            }

            var line = new StringBuilder(formatter(state, exception));
            provider._scopes.ForEachScope((scope, builder) => builder.Append(" | ").Append(scope), line);
            provider.Messages.Enqueue(line.ToString());
        }
    }
}
```

- [ ] **Step 2: Write the audit tests**

```csharp
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class AuthAuditTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private (WebApplicationFactory<Program> App, CapturingLoggerProvider Logs, CapturingLoginEmailSender Sender) Create(bool challenge)
    {
        var logs = new CapturingLoggerProvider();
        var sender = new CapturingLoginEmailSender();
        var app = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Login:ConfirmationEnabled"] = challenge ? "true" : "false",
                ["Frontend:Origin"] = "https://app.example.test"
            }));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ILoginEmailSender>();
                services.AddSingleton<ILoginEmailSender>(sender);
                services.AddControllers().AddApplicationPart(typeof(ProtectedTestController).Assembly);
            });
            builder.ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddProvider(logs);
            });
        });
        return (app, logs, sender);
    }

    private static void AssertNoSecrets(IEnumerable<string> logs, params string[] secrets)
    {
        Assert.All(logs, line =>
        {
            foreach (var secret in secrets)
            {
                Assert.DoesNotContain(secret, line, StringComparison.Ordinal);
            }

            Assert.DoesNotContain("@", line, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task DirectSession_LogsEventsWithIdsAndNoSecrets()
    {
        var (app, logs, _) = Create(challenge: false);
        using var _app = app;
        using var client = CreateClient(app);
        var email = NewEmail();
        var userId = await CreateUserAsync(app.Services, email);
        var unknownEmail = NewEmail();

        using var success = await LoginAsync(client, email);
        using var wrong = await LoginAsync(client, email, "wrong password 1");
        using var unknown = await LoginAsync(client, unknownEmail);
        var access = CookieValue(success, "access_token");
        var refresh = CookieValue(success, "refresh_token");
        using var refreshed = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={refresh}");
        using var badRefresh = await PostWithCookieAsync(client, "/auth/refresh", "refresh_token=garbage");
        using var rejectedAccess = await client.GetAsync("/test/protected");
        using var logout = await PostWithCookieAsync(client, "/auth/logout", $"access_token={access}");
        using var csrfRequest = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        csrfRequest.Headers.Add("Origin", "https://evil.example");
        using var csrf = await client.SendAsync(csrfRequest);

        var lines = logs.Messages.ToArray();
        Assert.Contains(lines, line => line.Contains("EventName=Login", StringComparison.Ordinal)
            && line.Contains($"UserId={userId}", StringComparison.Ordinal) && line.Contains("Outcome=success", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("EventName=Login", StringComparison.Ordinal)
            && line.Contains($"UserId={userId}", StringComparison.Ordinal) && line.Contains("Outcome=invalid_credentials", StringComparison.Ordinal));
        var emailRef = app.Services.GetRequiredService<AuthAudit>().EmailRef(unknownEmail);
        Assert.Contains(lines, line => line.Contains($"EmailRef={emailRef}", StringComparison.Ordinal)
            && line.Contains("Outcome=invalid_credentials", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("EventName=Refresh", StringComparison.Ordinal) && line.Contains("Outcome=success", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("EventName=Refresh", StringComparison.Ordinal) && line.Contains("Category=malformed", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("EventName=AccessRejected", StringComparison.Ordinal) && line.Contains("Category=missing", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("EventName=Logout", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("EventName=CsrfRejected", StringComparison.Ordinal) && line.Contains("Category=origin", StringComparison.Ordinal));
        Assert.All(lines, line => Assert.Contains("RequestId:", line, StringComparison.Ordinal));
        AssertNoSecrets(lines, Password, "wrong password 1", access, refresh);
    }

    [Fact]
    public async Task Challenge_LogsLifecycleWithoutCode()
    {
        var (app, logs, sender) = Create(challenge: true);
        using var _app = app;
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);

        using var login = await LoginAsync(client, email);
        var attemptId = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("attemptId").GetGuid();
        var code = sender.LastFor(email);
        using var wrong = await client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code = code == "000000" ? "111111" : "000000" });
        using var confirm = await client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code });

        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
        var lines = logs.Messages.Where(line => line.Contains("EventName=LoginChallenge", StringComparison.Ordinal)).ToArray();
        foreach (var outcome in new[] { "created", "wrong_entry", "confirmed" })
        {
            Assert.Contains(lines, line => line.Contains($"Outcome={outcome}", StringComparison.Ordinal)
                && line.Contains($"AttemptId={attemptId}", StringComparison.Ordinal)
                && line.Contains("Method=otp", StringComparison.Ordinal));
        }

        AssertNoSecrets(logs.Messages, Password, $"={code}", $" {code} ");
    }
}
```

`AssertNoSecrets` checks for `@` (no email address) and for the exact JWT values the test received. A random six-digit code could appear inside a Guid or a request id, so the code check matches `={code}` and ` {code} ` rather than the bare digits.

- [ ] **Step 3: Run the tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~AuthAuditTests"`
Expected: PASS. If `RequestId:` is missing, check that `CapturingLogger.IsEnabled` returns true for the hosting category; the scope is only created when that logger is enabled.

- [ ] **Step 4: Switch the app to structured JSON logs**

In `Program.cs`, right after `var builder = WebApplication.CreateBuilder(args);`:

```csharp
builder.Logging.ClearProviders();
builder.Logging.AddJsonConsole(options => options.IncludeScopes = true);
```

- [ ] **Step 5: Run all tests and check formatting**

```bash
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln
dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln --verify-no-changes
```

Expected: all tests PASS; `dotnet format` reports no changes (run `dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln` and re-check if it does).

- [ ] **Step 6: Commit**

```bash
git add src tests
git commit -m "feat: structured auth audit logs without secrets"
```

### Task 13: Configuration files and documentation

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/appsettings.json`
- Modify: `compose.yaml`
- Modify: `.gitignore`
- Modify: `docs/openapi.yaml`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-11-26-login-authentication-design.md`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/Auth/DirectLoginTests.cs`

- [ ] **Step 1: Write the failing OpenAPI test**

Append to `DirectLoginTests`:

```csharp
    [Fact]
    public async Task LoginEndpoints_AppearInOpenApiWithTheirStatuses()
    {
        using var client = CreateClient(factory);
        using var response = await client.GetAsync("/openapi/v1.json");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var paths = document.RootElement.GetProperty("paths");

        void AssertCodes(string path, params string[] expected)
        {
            var actual = paths.GetProperty(path).GetProperty("post").GetProperty("responses")
                .EnumerateObject().Select(item => item.Name).ToHashSet(StringComparer.Ordinal);
            Assert.Subset(expected.ToHashSet(StringComparer.Ordinal), actual);
        }

        AssertCodes("/auth/login", "202", "204", "400", "401", "403", "429", "503");
        AssertCodes("/auth/login/confirm", "204", "400", "401", "403", "429", "503");
        AssertCodes("/auth/login/resend", "202", "400", "401", "403", "429", "503");
        AssertCodes("/auth/refresh", "204", "401", "403", "429", "503");
        AssertCodes("/auth/logout", "204", "403");
    }
```

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter "FullyQualifiedName~LoginEndpoints_AppearInOpenApi"`
Expected: PASS already (the attributes were added in Tasks 5–9). If it fails, add the missing `ProducesResponseType` to the action it names.

- [ ] **Step 2: Non-secret JWT settings in `appsettings.json`**

Add a top-level section (issuer and audience are not secrets):

```json
  "Jwt": {
    "Issuer": "groupa1-api",
    "Audience": "groupa1-web"
  },
```

- [ ] **Step 3: Pass the keys to Docker Compose from the shell or a local `.env`**

In `compose.yaml`, under `api.environment`, add:

```yaml
      Jwt__AccessSecret: ${JWT_ACCESS_SECRET:?set JWT_ACCESS_SECRET, see README}
      Jwt__RefreshSecret: ${JWT_REFRESH_SECRET:?set JWT_REFRESH_SECRET, see README}
      Login__ChallengeHmacKey: ${LOGIN_CHALLENGE_HMAC_KEY:?set LOGIN_CHALLENGE_HMAC_KEY, see README}
      Login__AuditHmacKey: ${LOGIN_AUDIT_HMAC_KEY:?set LOGIN_AUDIT_HMAC_KEY, see README}
```

Append to `.gitignore` under `# Logs and local configuration`:

```text
.env
```

- [ ] **Step 4: Extend `docs/openapi.yaml`**

Change `info.title` to `Registration and Authentication API` and the first sentence of `info.description` to `HTTP contract for the application's health, account-registration and sign-in endpoints.` Add `- name: Authentication` under `tags`. Insert these paths directly before `components:`:

```yaml
  /auth/login:
    post:
      tags: [Authentication]
      operationId: login
      summary: Sign in with email and password
      description: >-
        Signs in directly (204 with access_token and refresh_token cookies) or, when the server
        enables sign-in confirmation, sends an OTP or a magic link and returns 202. Unknown email,
        wrong password and any non-active status return the same 401. At most 30 requests per IP
        per minute and 5 failed checks per email and IP per 15 minutes.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '204':
          description: Signed in. Sets both cookies; no body.
          headers:
            Set-Cookie:
              $ref: '#/components/headers/SessionCookies'
        '202':
          description: Confirmation required; the secret was sent by email only.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginChallengeResponse'
        '400':
          $ref: '#/components/responses/ValidationError'
        '401':
          $ref: '#/components/responses/InvalidCredentials'
        '403':
          $ref: '#/components/responses/CsrfRejected'
        '429':
          $ref: '#/components/responses/RetryAfter'
        '503':
          description: >-
            Database, token signing or SMTP unavailable. After an SMTP failure the attempt is kept
            and the body carries its id; retry through resend after retryAfterSeconds.
          content:
            application/json:
              schema:
                oneOf:
                  - $ref: '#/components/schemas/LoginChallengeFailedResponse'
                  - $ref: '#/components/schemas/ErrorResponse'
  /auth/login/confirm:
    post:
      tags: [Authentication]
      operationId: confirmLogin
      summary: Confirm sign-in with an OTP or a magic-link token
      description: >-
        OTP allows 5 entries; the fifth incorrect entry consumes the attempt and the next one returns 429.
        A magic-link page reads the token from the URL fragment and posts it here; GET never confirms.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginConfirmRequest'
      responses:
        '204':
          description: Signed in. Sets both cookies; no body.
          headers:
            Set-Cookie:
              $ref: '#/components/headers/SessionCookies'
        '400':
          $ref: '#/components/responses/InvalidChallenge'
        '401':
          $ref: '#/components/responses/InvalidCredentials'
        '403':
          $ref: '#/components/responses/CsrfRejected'
        '429':
          description: All 5 OTP entries were used. Sign in again.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '503':
          $ref: '#/components/responses/ServiceUnavailable'
  /auth/login/resend:
    post:
      tags: [Authentication]
      operationId: resendLogin
      summary: Send a new code or link for an attempt
      description: >-
        Allowed 60 seconds after the last send, also after expiry. Keeps the attempt's method,
        replaces the secret and resets the OTP counter.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginResendRequest'
      responses:
        '202':
          description: New secret sent.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResendResponse'
        '400':
          $ref: '#/components/responses/InvalidChallenge'
        '401':
          $ref: '#/components/responses/InvalidCredentials'
        '403':
          $ref: '#/components/responses/CsrfRejected'
        '429':
          $ref: '#/components/responses/RetryAfter'
        '503':
          $ref: '#/components/responses/ServiceUnavailable'
  /auth/refresh:
    post:
      tags: [Authentication]
      operationId: refreshSession
      summary: Issue a new token pair from the refresh cookie
      description: >-
        Reads only the refresh_token cookie. The used refresh token is not revoked and stays valid
        until its own exp. At most 30 requests per IP per minute.
      responses:
        '204':
          description: New pair set in both cookies; no body.
          headers:
            Set-Cookie:
              $ref: '#/components/headers/SessionCookies'
        '401':
          $ref: '#/components/responses/InvalidSession'
        '403':
          $ref: '#/components/responses/CsrfRejected'
        '429':
          $ref: '#/components/responses/RetryAfter'
        '503':
          $ref: '#/components/responses/ServiceUnavailable'
  /auth/logout:
    post:
      tags: [Authentication]
      operationId: logout
      summary: Clear both session cookies
      description: Needs no valid token. Does not revoke copies of the refresh token on other devices.
      responses:
        '204':
          description: Both cookies cleared with Max-Age=0; no body.
        '403':
          $ref: '#/components/responses/CsrfRejected'
```

Under `components:`, add a `headers:` block before `responses:`:

```yaml
  headers:
    SessionCookies:
      description: >-
        access_token (HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900) and
        refresh_token (HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age=2592000), no Domain.
        A cross-site frontend configuration uses SameSite=None.
      schema:
        type: string
```

Append under `components.responses`:

```yaml
    InvalidCredentials:
      description: Unknown email, wrong password or inactive account; one identical response.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          example:
            code: invalid_credentials
            message: Email or password is incorrect.
    InvalidSession:
      description: Missing, invalid or expired token, wrong token type, or inactive user.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          example:
            code: invalid_session
            message: The session is missing or no longer valid.
    InvalidChallenge:
      description: Bad format, unknown, expired, replaced or already used attempt, or a wrong code or link.
      content:
        application/json:
          schema:
            oneOf:
              - $ref: '#/components/schemas/ErrorResponse'
              - $ref: '#/components/schemas/ValidationProblem'
    CsrfRejected:
      description: Untrusted Origin, or a trusted cross-origin request without X-CSRF-Protection 1.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
          example:
            code: csrf_rejected
            message: The request origin is not allowed.
    RetryAfter:
      description: Rate limit or 60-second email pause. Also sends a Retry-After header.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/RetryAfterResponse'
    ServiceUnavailable:
      description: Database, token signing or SMTP unavailable.
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
```

Append under `components.schemas` (after `ValidationProblem`):

```yaml
    LoginRequest:
      type: object
      required: [email, password]
      properties:
        email:
          type: string
          format: email
          description: Trimmed and lowercased by the server.
        password:
          type: string
          description: Used exactly as sent.
    LoginConfirmRequest:
      oneOf:
        - type: object
          additionalProperties: false
          required: [attemptId, code]
          properties:
            attemptId:
              type: string
              format: uuid
            code:
              type: string
              pattern: '^[0-9]{6}$'
        - type: object
          additionalProperties: false
          required: [token]
          properties:
            token:
              type: string
              description: '{attemptId}.{secret} from the magic-link URL fragment.'
              pattern: '^[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{43}$'
    LoginResendRequest:
      type: object
      required: [attemptId]
      properties:
        attemptId:
          type: string
          format: uuid
    LoginChallengeResponse:
      type: object
      required: [confirmationRequired, method, attemptId, expiresInSeconds, resendAfterSeconds]
      properties:
        confirmationRequired:
          type: boolean
          const: true
        method:
          type: string
          enum: [otp, magic_link]
        attemptId:
          type: string
          format: uuid
        expiresInSeconds:
          type: integer
          const: 600
        resendAfterSeconds:
          type: integer
          const: 60
    LoginChallengeFailedResponse:
      type: object
      required: [confirmationRequired, method, attemptId, retryAfterSeconds]
      properties:
        confirmationRequired:
          type: boolean
          const: true
        method:
          type: string
          enum: [otp, magic_link]
        attemptId:
          type: string
          format: uuid
        retryAfterSeconds:
          type: integer
    LoginResendResponse:
      type: object
      required: [method, attemptId, expiresInSeconds, resendAfterSeconds]
      properties:
        method:
          type: string
          enum: [otp, magic_link]
        attemptId:
          type: string
          format: uuid
        expiresInSeconds:
          type: integer
          const: 600
        resendAfterSeconds:
          type: integer
          const: 60
    ErrorResponse:
      type: object
      required: [code, message]
      properties:
        code:
          type: string
          enum: [invalid_credentials, invalid_session, invalid_challenge, too_many_requests, csrf_rejected, https_required, service_unavailable]
        message:
          type: string
    RetryAfterResponse:
      type: object
      required: [code, message, retryAfterSeconds]
      properties:
        code:
          type: string
          const: too_many_requests
        message:
          type: string
        retryAfterSeconds:
          type: integer
```

Check the file parses:

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('docs/openapi.yaml')); print('ok')"
```

Expected: `ok`. If PyYAML is missing, use `npx -y @redocly/cli@1.34.0 lint docs/openapi.yaml`.

- [ ] **Step 5: Add sample requests to the `.http` file**

Append:

```http
### Sign in (cookies are kept by the client between requests)
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "abc12345"
}

### Confirm sign-in with the OTP from Mailpit (http://localhost:8025)
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/login/confirm
Content-Type: application/json

{
  "attemptId": "attempt-id-from-login-response",
  "code": "123456"
}

### Confirm sign-in with the token after #token= in the magic link
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/login/confirm
Content-Type: application/json

{
  "token": "attempt-id.secret-from-magic-link"
}

### Send a new code or link (60 seconds after the last one)
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/login/resend
Content-Type: application/json

{
  "attemptId": "attempt-id-from-login-response"
}

### Refresh the token pair (uses the refresh_token cookie)
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/refresh

### Sign out
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/logout

###
```

Cookies are `Secure`. Over the plain-HTTP profile, clients other than browsers on `localhost` may not send them back; use `--launch-profile https` and `https://localhost:7135` for refresh.

- [ ] **Step 6: README**

In `## Endpoints`, add rows to the table:

```markdown
| `POST` | `/auth/login` | Sign in; sets cookies or starts an email challenge. |
| `POST` | `/auth/login/confirm` | Confirm sign-in with an OTP or a magic-link token. |
| `POST` | `/auth/login/resend` | Send a new code or link for an attempt. |
| `POST` | `/auth/refresh` | New token pair from the refresh cookie. |
| `POST` | `/auth/logout` | Clear both session cookies. |
```

Insert a new section after `## Run with Docker Desktop`:

````markdown
## Authentication keys

The API refuses to start without four random keys of at least 32 bytes, all different:
`Jwt:AccessSecret`, `Jwt:RefreshSecret`, `Login:ChallengeHmacKey`, `Login:AuditHmacKey`.
Nothing in the repository provides them.

For `dotnet run`, store them in user secrets once:

```bash
for key in Jwt:AccessSecret Jwt:RefreshSecret Login:ChallengeHmacKey Login:AuditHmacKey; do
  dotnet user-secrets set "$key" "$(openssl rand -base64 32)" --project src/FEDept.BackendCourse.GroupA1.Api.Template
done
```

For Docker Compose, put them in a local `.env` file next to `compose.yaml` (it is git-ignored):

```bash
for name in JWT_ACCESS_SECRET JWT_REFRESH_SECRET LOGIN_CHALLENGE_HMAC_KEY LOGIN_AUDIT_HMAC_KEY; do
  echo "$name=$(openssl rand -base64 32)" >> .env
done
```

Other sign-in settings:

| Key | Default | Meaning |
| --- | --- | --- |
| `Login:ConfirmationEnabled` | `false` | Require an emailed OTP or link after the password. |
| `Login:ConfirmationMethod` | `Otp` | `Otp` or `MagicLink`; applies to new attempts only. |
| `Login:MagicLinkBaseUrl` | — | Frontend page that reads `#token=` and posts it to `/auth/login/confirm`. Required for `MagicLink`. |
| `Jwt:Issuer`, `Jwt:Audience` | `groupa1-api`, `groupa1-web` | Must match on issue and verification. |
| `Frontend:Origin` | — | Exact trusted frontend origin for CORS with credentials. |
| `Frontend:CrossSite` | `false` | `true` switches the cookies to `SameSite=None`. |

Cross-origin browser POSTs must send `X-CSRF-Protection: 1` and `credentials: "include"`.
````

Replace the `## Frontend integration` section body with:

```markdown
Set `Frontend:Origin` to the frontend's exact origin (for example `http://localhost:3000`). CORS then allows that origin with credentials and the `Content-Type` and `X-CSRF-Protection` headers. Requests from any other origin are rejected with `403 csrf_rejected`.
```

Replace the sentence under `## Test` that says the tests only verify `GET /health` with:

```markdown
Tests start PostgreSQL in Docker through Testcontainers, so Docker must be running.
```

- [ ] **Step 7: Refresh `CLAUDE.md` architecture**

Replace the `## Architecture` section body with:

```markdown
ASP.NET Core Web API for internship exercises with two projects plus tests. `Infrastructure` holds EF Core (`AppDbContext`, PostgreSQL via Npgsql, migrations), `Registration/` (sign-up with OTP or magic-link confirmation) and `Authentication/` (`LoginService`, `JwtTokenService`, `login_challenges`, `FailedLoginLimiter`, `AuthAudit`). The API project holds controllers, contracts and `Authentication/` (cookie helper, `AccessCookie` authentication handler, CSRF and HTTPS middleware, startup validation of auth settings).

`Program.cs` is the composition root. Auth keys are required at startup (user secrets locally, `.env` for Compose). Tests run the API in memory through `WebApplicationFactory<Program>` against a Testcontainers PostgreSQL; `RegistrationTestFactory` injects random keys. Development applies migrations on startup when `Database:ApplyMigrations` is true. The OpenAPI contract is maintained by hand in `docs/openapi.yaml`.
```

- [ ] **Step 8: Record the planning deviations in the spec**

Add a section at the end of `docs/superpowers/specs/2026-11-26-login-authentication-design.md`:

```markdown
## Changes made during planning

- Sign-in emails go through a new `ILoginEmailSender`; `IEmailSender` is unchanged.
- IP permits are configurable (`Login:LoginPermitPerMinute`, `Login:RefreshPermitPerMinute`, default 30).
- The HTTPS guard and HSTS run outside Development only; Compose and the `.http` samples use plain HTTP locally.
- The 429 for exhausted OTP entries has no `Retry-After`; the client signs in again.
- `LoginChallenge` audit outcomes also include `rejected` and `cooldown`.
- `EmailDeliveryException` is not mapped by the exception handler; login and resend handle SMTP failure themselves.
- `Jwt:Issuer` and `Jwt:Audience` live in `appsettings.json`; only the four keys are secret.
- The IP rate limiter runs before model validation, so malformed requests count toward the 30 per minute.
- The failed-login limiter reserves a slot before BCrypt and releases it on success or outage, so concurrent guesses cannot exceed 5.
- The access-cookie handler skips endpoints without `[Authorize]`, so anonymous routes (logout, health) never query users and keep working during a database outage.
- Confirm and resend return two 400 shapes: `ValidationProblemDetails` for a malformed body and `ErrorResponse` `invalid_challenge` for a rejected challenge. `docs/openapi.yaml` documents both.
- `too_many_requests` has two fixed messages: one for the IP and failed-login limits, one for exhausted OTP entries.
```

- [ ] **Step 9: Final verification**

```bash
dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln --verify-no-changes
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --collect:"XPlat Code Coverage"
```

Expected: build succeeds, no format changes, all tests PASS. Coverage report lands under `tests/**/TestResults/*/coverage.cobertura.xml`; check `line-rate` ≥ 0.8 on the root element:

```bash
grep -o 'line-rate="[0-9.]*"' -m1 tests/*/TestResults/*/coverage.cobertura.xml
```

- [ ] **Step 10: Commit**

`CLAUDE.md` is untracked in this repository; edit it but do not add it unless the user asks.

```bash
git add .gitignore compose.yaml README.md docs src tests
git commit -m "docs: sign-in contract, key setup and configuration"
```

