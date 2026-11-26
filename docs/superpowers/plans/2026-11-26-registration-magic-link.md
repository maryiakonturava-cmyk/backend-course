# Registration Magic Link Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `magic_link` as a second registration confirmation method next to OTP, selected by server configuration.

**Architecture:** Extend the existing `RegistrationService` in place. A new token generator produces 32 random bytes (base64url). The challenge row stores the method and the HMAC of the secret. Register and resend pick the secret type and email by method. `POST /auth/register/confirm` accepts either `{attemptId, code}` or `{token}`; the token path finds the challenge by HMAC. No schema migration.

**Tech Stack:** .NET 10, ASP.NET Core controllers, EF Core + Npgsql, MailKit, xUnit + `WebApplicationFactory` + Testcontainers PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-11-26-registration-magic-link-design.md`

**Prerequisites:** Docker running (integration tests start a `postgres:16-alpine` container).

---

## File structure

| File | Change | Responsibility |
| --- | --- | --- |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/MagicLinkTokenGenerator.cs` | create | 32-byte base64url token |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/ChallengeMethod.cs` | modify | add `MagicLink`, contract-name mapping |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationOptions.cs` | modify | `ConfirmationMethod`, `MagicLinkBaseUrl` |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/IEmailSender.cs` | modify | `SendMagicLinkAsync` |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/SmtpEmailSender.cs` | modify | link email |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationAudit.cs` | modify | `Method` field on send event |
| `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs` | modify | method branching, token confirm |
| `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs` | modify | startup validation |
| `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/ConfirmRequest.cs` | modify | two body shapes |
| `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs` | modify | method in responses, confirm dispatch |
| `src/FEDept.BackendCourse.GroupA1.Api.Template/appsettings.Development.json` | modify | link base URL |
| `src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http` | modify | sample token confirm |
| `docs/openapi.yaml` | modify | confirm `oneOf`, `method` enum |
| `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkTokenGeneratorTests.cs` | create | generator unit test |
| `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs` | create | magic link integration tests |
| `tests/.../AuditLoggingTests.cs`, `RegisterEndpointTests.cs`, `ResendEndpointTests.cs`, `ConfirmEndpointTests.cs` | modify | fakes implement new interface member; audit test |

Solution file for all commands: `FEDept.BackendCourse.GroupA1.Api.Template.sln` (run from repo root).

---

### Task 1: Magic link token generator

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/MagicLinkTokenGenerator.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkTokenGeneratorTests.cs`

- [ ] **Step 1: Write the failing test**

```csharp
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class MagicLinkTokenGeneratorTests
{
    [Fact]
    public void Generate_Returns43Base64UrlCharsAndDistinctValues()
    {
        var tokens = Enumerable.Range(0, 100).Select(_ => MagicLinkTokenGenerator.Generate()).ToList();

        Assert.All(tokens, token => Assert.Matches("^[A-Za-z0-9_-]{43}$", token));
        Assert.Equal(tokens.Count, tokens.Distinct().Count());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~MagicLinkTokenGeneratorTests`
Expected: build FAIL, `The name 'MagicLinkTokenGenerator' does not exist in the current context`.

- [ ] **Step 3: Write minimal implementation**

```csharp
using System.Buffers.Text;
using System.Security.Cryptography;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public static class MagicLinkTokenGenerator
{
    public static string Generate() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~MagicLinkTokenGeneratorTests`
Expected: PASS, 1 test.

- [ ] **Step 5: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/MagicLinkTokenGenerator.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkTokenGeneratorTests.cs
git commit -m "feat: add magic link token generator"
```

---

### Task 2: `SendMagicLinkAsync` on the email sender

Interface change only; every implementation must compile. No behavior uses it yet.

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/IEmailSender.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/SmtpEmailSender.cs`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/AuditLoggingTests.cs` (class `CapturingEmailSender`)
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/RegisterEndpointTests.cs` (class `CapturingEmailSender`)
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/ResendEndpointTests.cs` (classes `CapturingEmailSender`, `ThrowingEmailSender`)
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/ConfirmEndpointTests.cs` (class `CapturingEmailSender`)

- [ ] **Step 1: Replace `IEmailSender.cs` content**

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public interface IEmailSender
{
    Task SendOtpAsync(string email, string code, CancellationToken ct);

    Task SendMagicLinkAsync(string email, string link, CancellationToken ct);
}

public sealed class NullEmailSender : IEmailSender
{
    public Task SendOtpAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;

    public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) => Task.CompletedTask;
}
```

- [ ] **Step 2: Replace `SmtpEmailSender.cs` content**

```csharp
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailSender
{
    public Task SendOtpAsync(string email, string code, CancellationToken ct) =>
        SendAsync(email, "Registration verification code", $"Your verification code is {code}.", ct);

    public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) =>
        SendAsync(email, "Confirm your registration", $"Open this link to confirm your registration: {link}", ct);

    private async Task SendAsync(string email, string subject, string text, CancellationToken ct)
    {
        var message = new MimeMessage
        {
            Subject = subject,
            Body = new TextPart("plain") { Text = text }
        };
        message.From.Add(MailboxAddress.Parse(options.Value.From));
        message.To.Add(MailboxAddress.Parse(email));

        using var client = new SmtpClient();
        await client.ConnectAsync(options.Value.Host, options.Value.Port, SecureSocketOptions.Auto, ct);
        await client.SendAsync(FormatOptions.Default, new SmtpSendRequest(message), ct);
        await client.DisconnectAsync(true, ct);
    }
}
```

- [ ] **Step 3: Add the member to each test fake**

In `AuditLoggingTests.cs`, `RegisterEndpointTests.cs`, `ConfirmEndpointTests.cs`, and the `CapturingEmailSender` in `ResendEndpointTests.cs`, add directly below the existing `SendOtpAsync` method:

```csharp

        public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) => Task.CompletedTask;
```

In `ResendEndpointTests.cs`, replace the `ThrowingEmailSender` class with:

```csharp
    private sealed class ThrowingEmailSender : IEmailSender
    {
        public Task SendOtpAsync(string email, string code, CancellationToken ct) =>
            Task.FromException(new InvalidOperationException("SMTP unavailable"));

        public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) =>
            Task.FromException(new InvalidOperationException("SMTP unavailable"));
    }
```

- [ ] **Step 4: Build and run the full suite**

Run: `dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln && dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: build succeeds, all tests PASS (no behavior changed).

- [ ] **Step 5: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/IEmailSender.cs src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/SmtpEmailSender.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/AuditLoggingTests.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/RegisterEndpointTests.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/ResendEndpointTests.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/ConfirmEndpointTests.cs
git commit -m "feat: add SendMagicLinkAsync to email sender"
```

---

### Task 3: Configuration and startup validation

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/ChallengeMethod.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationOptions.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs:13-17`
- Create: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs`

- [ ] **Step 1: Write the failing test (new file with the shared fixture code used by later tasks)**

```csharp
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class MagicLinkEndpointTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private const string HmacKey = "test-magic-link-hmac-key";
    private const string BaseUrl = "http://localhost:3000/register/confirm";
    private readonly RegistrationTestFactory _factory;
    private readonly CapturingEmailSender _emailSender = new();
    private readonly HttpClient _client;

    public MagicLinkEndpointTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _client = CreateClient("MagicLink", BaseUrl);
    }

    [Theory]
    [InlineData("")]
    [InlineData("/register/confirm")]
    public void Startup_FailsWhenMagicLinkBaseUrlIsNotAbsoluteHttpUrl(string baseUrl)
    {
        var exception = Record.Exception(() => CreateClient("MagicLink", baseUrl));

        Assert.NotNull(exception);
        Assert.Contains("Registration:MagicLinkBaseUrl", exception.ToString(), StringComparison.Ordinal);
    }

    private HttpClient CreateClient(string method, string baseUrl) => _factory.WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Registration:ConfirmationEnabled"] = "true",
                ["Registration:ConfirmationMethod"] = method,
                ["Registration:MagicLinkBaseUrl"] = baseUrl,
                ["Registration:HmacKey"] = HmacKey,
                ["Registration:RateLimitPermitPerWindow"] = "1000"
            }));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(_emailSender);
        });
    }).CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });

    public void Dispose() => _client.Dispose();

    private sealed class CapturingEmailSender : IEmailSender
    {
        public ConcurrentQueue<(string Email, string Link)> Links { get; } = new();

        public Task SendOtpAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;

        public Task SendMagicLinkAsync(string email, string link, CancellationToken ct)
        {
            Links.Enqueue((email, link));
            return Task.CompletedTask;
        }
    }
}
```

`/register/confirm` is in the theory on purpose: on macOS/Linux `Uri.TryCreate("/register/confirm", UriKind.Absolute, ...)` returns `true` (a `file://` URI), so the validation must also check the scheme.

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~MagicLinkEndpointTests`
Expected: 2 FAIL, `Assert.NotNull() Failure: Value is null` (no validation yet; `ConfirmationMethod` is not bound and is ignored).

- [ ] **Step 3: Replace `ChallengeMethod.cs` content**

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public enum ChallengeMethod
{
    Otp,
    MagicLink
}

public static class ChallengeMethodExtensions
{
    public static string ToContractName(this ChallengeMethod method) => method switch
    {
        ChallengeMethod.Otp => "otp",
        ChallengeMethod.MagicLink => "magic_link",
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, null)
    };
}
```

- [ ] **Step 4: Replace `RegistrationOptions.cs` content**

```csharp
namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class RegistrationOptions
{
    public bool ConfirmationEnabled { get; set; }

    public ChallengeMethod ConfirmationMethod { get; set; } = ChallengeMethod.Otp;

    public string MagicLinkBaseUrl { get; set; } = string.Empty;

    public string HmacKey { get; set; } = string.Empty;

    public int RateLimitPermitPerWindow { get; set; }
}
```

- [ ] **Step 5: Add the validation in `Program.cs`**

Replace:

```csharp
    .Validate(options => !options.ConfirmationEnabled || !string.IsNullOrWhiteSpace(options.HmacKey),
        "Registration:HmacKey must be configured when confirmation is enabled.")
    .ValidateOnStart();
```

with:

```csharp
    .Validate(options => !options.ConfirmationEnabled || !string.IsNullOrWhiteSpace(options.HmacKey),
        "Registration:HmacKey must be configured when confirmation is enabled.")
    .Validate(options => !options.ConfirmationEnabled
            || options.ConfirmationMethod != ChallengeMethod.MagicLink
            || (Uri.TryCreate(options.MagicLinkBaseUrl, UriKind.Absolute, out var baseUrl)
                && (baseUrl.Scheme == Uri.UriSchemeHttp || baseUrl.Scheme == Uri.UriSchemeHttps)),
        "Registration:MagicLinkBaseUrl must be an absolute URL when the magic link method is enabled.")
    .ValidateOnStart();
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS, including both `Startup_FailsWhenMagicLinkBaseUrlIsNotAbsoluteHttpUrl` cases.

- [ ] **Step 7: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/ChallengeMethod.cs src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationOptions.cs src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs
git commit -m "feat: magic link confirmation method config and startup validation"
```

---

### Task 4: Register sends the magic link

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationAudit.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs`
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs`

- [ ] **Step 1: Write the failing test**

In `MagicLinkEndpointTests.cs`, add `using System.Text.Json;` to the usings, then add this test after `Startup_FailsWhenMagicLinkBaseUrlIsNotAbsoluteHttpUrl`:

```csharp
    [Fact]
    public async Task Register_SendsMagicLinkAndReturnsMethodWithoutToken()
    {
        var email = NewEmail();

        using var response = await RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        var body = JsonSerializer.Deserialize<ConfirmationRequiredResponse>(json, JsonSerializerOptions.Web);
        Assert.NotNull(body);
        Assert.Equal("magic_link", body.Method);
        Assert.Equal(600, body.ExpiresInSeconds);
        Assert.Equal(60, body.ResendAfterSeconds);
        var token = TokenFor(email);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", token);
        Assert.DoesNotContain(token, json, StringComparison.Ordinal);
        using var scope = _factory.Services.CreateScope();
        var challenge = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .RegistrationChallenges.SingleAsync(item => item.Id == body.AttemptId);
        Assert.Equal(ChallengeMethod.MagicLink, challenge.Method);
        Assert.Equal(new SecretHasher(HmacKey).Hash(token), challenge.SecretHash);
    }
```

And add these helpers below `CreateClient`:

```csharp
    private Task<HttpResponseMessage> RegisterAsync(string email) =>
        _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "abc12345"));

    private string TokenFor(string email)
    {
        var link = _emailSender.Links.Last(item => item.Email == email).Link;
        Assert.StartsWith($"{BaseUrl}?token=", link, StringComparison.Ordinal);
        return link[$"{BaseUrl}?token=".Length..];
    }

    private static string NewEmail() => $"{Guid.NewGuid():N}@example.com";
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~Register_SendsMagicLinkAndReturnsMethodWithoutToken`
Expected: FAIL on `Assert.Equal("magic_link", body.Method)` (actual `"otp"`).

- [ ] **Step 3: Add the method to the send audit event**

In `RegistrationAudit.cs`, replace `RegistrationCodeSent` with:

```csharp
    public static void RegistrationCodeSent(ILogger logger, string email, string method, string outcome) =>
        logger.LogInformation("Registration audit EventName={EventName} Email={Email} Method={Method} Outcome={Outcome}",
            nameof(RegistrationCodeSent), email, method, outcome);
```

- [ ] **Step 4: Branch register on the method in `RegistrationService.cs`**

Replace:

```csharp
            var code = confirmationEnabled ? OtpGenerator.Generate() : null;
            var challenge = confirmationEnabled
                ? new RegistrationChallenge
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Method = ChallengeMethod.Otp,
                    SecretHash = new SecretHasher(options.Value.HmacKey).Hash(code!),
```

with:

```csharp
            var method = options.Value.ConfirmationMethod;
            var secret = confirmationEnabled ? GenerateSecret(method) : null;
            var challenge = confirmationEnabled
                ? new RegistrationChallenge
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Method = method,
                    SecretHash = new SecretHasher(options.Value.HmacKey).Hash(secret!),
```

Replace:

```csharp
                if (code is not null)
                {
                    await SendOtpAsync(normalizedEmail, code, ct);
                    RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "success");
                    return new RegisterResult.ConfirmationRequired(challenge!.Id);
                }
```

with:

```csharp
                if (secret is not null)
                {
                    await SendSecretAsync(normalizedEmail, method, secret, ct);
                    RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "success");
                    return new RegisterResult.ConfirmationRequired(challenge!.Id, method);
                }
```

In `ResendAsync`, replace (resend keeps generating OTP until Task 6):

```csharp
        await SendOtpAsync(user.Email, code, ct);
```

with:

```csharp
        await SendSecretAsync(user.Email, ChallengeMethod.Otp, code, ct);
```

Replace the whole private `SendOtpAsync` method with:

```csharp
    private static string GenerateSecret(ChallengeMethod method) =>
        method == ChallengeMethod.MagicLink ? MagicLinkTokenGenerator.Generate() : OtpGenerator.Generate();

    private string BuildMagicLink(string token)
    {
        var baseUrl = options.Value.MagicLinkBaseUrl;
        // base64url token needs no escaping
        return $"{baseUrl}{(baseUrl.Contains('?') ? '&' : '?')}token={token}";
    }

    private async Task SendSecretAsync(string email, ChallengeMethod method, string secret, CancellationToken ct)
    {
        try
        {
            if (method == ChallengeMethod.MagicLink)
            {
                await emailSender.SendMagicLinkAsync(email, BuildMagicLink(secret), ct);
            }
            else
            {
                await emailSender.SendOtpAsync(email, secret, ct);
            }

            RegistrationAudit.RegistrationCodeSent(logger, email, method.ToContractName(), "success");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            RegistrationAudit.RegistrationCodeSent(logger, email, method.ToContractName(), "failure");
            throw new EmailDeliveryException(exception);
        }
    }
```

Replace the `ConfirmationRequired` record in `RegisterResult` with:

```csharp
    public sealed record ConfirmationRequired(Guid AttemptId, ChallengeMethod Method) : RegisterResult;
```

- [ ] **Step 5: Map the method in `RegistrationController.Register`**

Replace:

```csharp
            RegisterResult.ConfirmationRequired confirmation => Accepted(
                new ConfirmationRequiredResponse(true, "otp", confirmation.AttemptId, 600, 60)),
```

with:

```csharp
            RegisterResult.ConfirmationRequired confirmation => Accepted(
                new ConfirmationRequiredResponse(true, confirmation.Method.ToContractName(), confirmation.AttemptId, 600, 60)),
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS (existing audit test still finds `RegistrationCodeSent` + email + `success`).

- [ ] **Step 7: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationAudit.cs src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs
git commit -m "feat: send magic link on registration when configured"
```

---

### Task 5: Confirm by token

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/ConfirmRequest.cs`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs` (`ConfirmAsync`)
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs` (`Confirm`)
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs`

- [ ] **Step 1: Write the failing tests**

Add to `MagicLinkEndpointTests.cs` after `Register_SendsMagicLinkAndReturnsMethodWithoutToken`:

```csharp
    [Fact]
    public async Task RegisterThenConfirmToken_ActivatesUserAndConsumesChallenge()
    {
        var email = NewEmail();
        using var registration = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, registration.StatusCode);

        using var confirmation = await ConfirmTokenAsync(TokenFor(email));

        Assert.Equal(HttpStatusCode.OK, confirmation.StatusCode);
        var body = await confirmation.Content.ReadFromJsonAsync<ConfirmedResponse>();
        Assert.NotNull(body);
        Assert.Equal(email, body.Email);
        Assert.Equal("active", body.Status);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.SingleAsync(item => item.Email == email);
        Assert.Equal(body.Id, user.Id);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.NotNull((await db.RegistrationChallenges.SingleAsync(item => item.UserId == user.Id)).ConsumedAt);
    }

    [Fact]
    public async Task ConfirmToken_ReusedTokenReturnsBadRequest()
    {
        var token = MagicLinkTokenGenerator.Generate();
        await SeedChallengeAsync(ChallengeMethod.MagicLink, token, DateTimeOffset.UtcNow.AddMinutes(10));
        using (var first = await ConfirmTokenAsync(token))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        using var second = await ConfirmTokenAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
    }

    [Fact]
    public async Task ConfirmToken_UnknownTokenReturnsBadRequest()
    {
        using var response = await ConfirmTokenAsync(MagicLinkTokenGenerator.Generate());

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ConfirmToken_ExpiredReturnsBadRequestAndKeepsUserPending()
    {
        var token = MagicLinkTokenGenerator.Generate();
        var (user, challenge) = await SeedChallengeAsync(ChallengeMethod.MagicLink, token, DateTimeOffset.UtcNow.AddSeconds(-1));

        using var response = await ConfirmTokenAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(UserStatus.Pending, (await db.Users.SingleAsync(item => item.Id == user.Id)).Status);
        Assert.Null((await db.RegistrationChallenges.SingleAsync(item => item.Id == challenge.Id)).ConsumedAt);
    }

    [Fact]
    public async Task ConfirmToken_ParallelSubmitsActivateOnce()
    {
        var token = MagicLinkTokenGenerator.Generate();
        await SeedChallengeAsync(ChallengeMethod.MagicLink, token, DateTimeOffset.UtcNow.AddMinutes(10));

        var responses = await Task.WhenAll(ConfirmTokenAsync(token), ConfirmTokenAsync(token));
        using var first = responses[0];
        using var second = responses[1];

        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ConfirmToken_AgainstOtpChallengeReturnsBadRequest()
    {
        var token = MagicLinkTokenGenerator.Generate();
        // same HMAC, wrong method: proves the lookup filters by method
        var (user, _) = await SeedChallengeAsync(ChallengeMethod.Otp, token, DateTimeOffset.UtcNow.AddMinutes(10));

        using var response = await ConfirmTokenAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(UserStatus.Pending, (await db.Users.SingleAsync(item => item.Id == user.Id)).Status);
    }

    [Fact]
    public async Task ConfirmCode_AgainstLinkChallengeReturnsBadRequestWithoutCountingAttempt()
    {
        // secret matches, method does not
        var (user, challenge) = await SeedChallengeAsync(ChallengeMethod.MagicLink, "654321", DateTimeOffset.UtcNow.AddMinutes(10));

        using var response = await _client.PostAsJsonAsync("/auth/register/confirm",
            new { attemptId = challenge.Id, code = "654321" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var saved = await db.RegistrationChallenges.SingleAsync(item => item.Id == challenge.Id);
        Assert.Equal(0, saved.Attempts);
        Assert.Null(saved.ConsumedAt);
        Assert.Equal(UserStatus.Pending, (await db.Users.SingleAsync(item => item.Id == user.Id)).Status);
    }

    [Fact]
    public async Task Confirm_InvalidBodyShapesReturnBadRequest()
    {
        var token = MagicLinkTokenGenerator.Generate();
        await SeedChallengeAsync(ChallengeMethod.MagicLink, token, DateTimeOffset.UtcNow.AddMinutes(10));
        object[] bodies =
        [
            new { attemptId = Guid.NewGuid(), code = "123456", token },
            new { code = "123456", token },
            new { attemptId = Guid.NewGuid(), token },
            new { attemptId = Guid.NewGuid() },
            new { token = "" },
            new { }
        ];

        foreach (var body in bodies)
        {
            using var response = await _client.PostAsJsonAsync("/auth/register/confirm", body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        // the valid token was never consumed by a rejected mixed body
        using var valid = await ConfirmTokenAsync(token);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
    }
```

Add these helpers below `TokenFor`:

```csharp
    private Task<HttpResponseMessage> ConfirmTokenAsync(string token) =>
        _client.PostAsJsonAsync("/auth/register/confirm", new { token });

    private async Task<(User User, RegistrationChallenge Challenge)> SeedChallengeAsync(
        ChallengeMethod method, string secret, DateTimeOffset expiresAt, DateTimeOffset? lastSentAt = null)
    {
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = NewEmail(),
            PasswordHash = "not-a-real-hash",
            Status = UserStatus.Pending,
            CreatedAt = now,
            UpdatedAt = now
        };
        var challenge = new RegistrationChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Method = method,
            SecretHash = new SecretHasher(HmacKey).Hash(secret),
            ExpiresAt = expiresAt,
            Attempts = 0,
            LastSentAt = lastSentAt ?? now,
            ConsumedAt = null
        };
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Users.Add(user);
        db.RegistrationChallenges.Add(challenge);
        await db.SaveChangesAsync();
        return (user, challenge);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~MagicLinkEndpointTests`
Expected: FAIL for `RegisterThenConfirmToken_ActivatesUserAndConsumesChallenge`, `ConfirmToken_ReusedTokenReturnsBadRequest`, `ConfirmToken_ParallelSubmitsActivateOnce`, `Confirm_InvalidBodyShapesReturnBadRequest` (each gets 400 instead of 200, because `{token}` is not accepted yet), and `ConfirmCode_AgainstLinkChallengeReturnsBadRequestWithoutCountingAttempt` (gets 200). The other 400-only tests may already pass; that is expected.

- [ ] **Step 3: Replace `ConfirmRequest.cs` content**

```csharp
using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

public sealed record ConfirmRequest(Guid? AttemptId, string? Code, string? Token = null) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var isOtp = AttemptId is not null && !string.IsNullOrEmpty(Code) && Token is null;
        var isLink = AttemptId is null && Code is null && !string.IsNullOrEmpty(Token);
        if (!isOtp && !isLink)
        {
            yield return new ValidationResult(
                "Provide either attemptId and code, or token.",
                [nameof(AttemptId), nameof(Code), nameof(Token)]);
        }
    }
}
```

`Token` defaults to `null` so the existing `new ConfirmRequest(attemptId, code)` calls in `AuditLoggingTests` and `ResendEndpointTests` keep compiling.

- [ ] **Step 4: Split confirm in `RegistrationService.cs`**

Rename `public async Task<ConfirmResult> ConfirmAsync(Guid attemptId, string code, CancellationToken ct)` to:

```csharp
    public async Task<ConfirmResult> ConfirmOtpAsync(Guid attemptId, string code, CancellationToken ct)
```

Inside it, replace:

```csharp
            if (user is null)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }
```

with:

```csharp
            if (user is null || challenge.Method != ChallengeMethod.Otp)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }
```

Replace its success tail:

```csharp
            user.Status = UserStatus.Active;
            user.UpdatedAt = now;
            challenge.ConsumedAt = now;
            // shortcut: assign user role here once RBAC module exists
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "success");
            return new ConfirmResult.Success(user);
```

with:

```csharp
            return await ActivateAsync(user, challenge, now, ct);
```

Add after `ConfirmOtpAsync`:

```csharp
    public async Task<ConfirmResult> ConfirmTokenAsync(string token, CancellationToken ct)
    {
        string? normalizedEmail = null;
        try
        {
            var secretHash = new SecretHasher(options.Value.HmacKey).Hash(token);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            // row lock: FOR UPDATE makes a concurrent double submit activate once
            var challenge = await db.RegistrationChallenges
                .FromSqlInterpolated($"SELECT * FROM \"registration_challenges\" WHERE \"secret_hash\" = {secretHash} AND \"method\" = {nameof(ChallengeMethod.MagicLink)} FOR UPDATE")
                .SingleOrDefaultAsync(ct);
            var user = challenge is null ? null : await db.Users.SingleOrDefaultAsync(item => item.Id == challenge.UserId, ct);
            normalizedEmail = user?.Email;
            var now = DateTimeOffset.UtcNow;
            if (challenge is null || user is null || challenge.ConsumedAt is not null || challenge.ExpiresAt <= now)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }

            return await ActivateAsync(user, challenge, now, ct);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
            throw;
        }
    }

    private async Task<ConfirmResult> ActivateAsync(
        User user, RegistrationChallenge challenge, DateTimeOffset now, CancellationToken ct)
    {
        user.Status = UserStatus.Active;
        user.UpdatedAt = now;
        challenge.ConsumedAt = now;
        // shortcut: assign user role here once RBAC module exists
        await db.SaveChangesAsync(ct);
        await db.Database.CommitTransactionAsync(ct);
        RegistrationAudit.RegistrationConfirm(logger, user.Email, "success");
        return new ConfirmResult.Success(user);
    }
```

- [ ] **Step 5: Dispatch in `RegistrationController.Confirm`**

Replace:

```csharp
        var result = await registrationService.ConfirmAsync(request.AttemptId, request.Code, ct);
```

with:

```csharp
        var result = request.Token is not null
            ? await registrationService.ConfirmTokenAsync(request.Token, ct)
            : await registrationService.ConfirmOtpAsync(request.AttemptId!.Value, request.Code!, ct);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS, including every existing `ConfirmEndpointTests` case.

- [ ] **Step 7: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template/Contracts/ConfirmRequest.cs src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs
git commit -m "feat: confirm registration by magic link token"
```

---

### Task 6: Resend follows the stored method

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs` (`ResendAsync`, `ResendResult`)
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs` (`Resend`)
- Test: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs`

- [ ] **Step 1: Write the failing test**

Add after `Confirm_InvalidBodyShapesReturnBadRequest`:

```csharp
    [Fact]
    public async Task Resend_UsesStoredMethodAndReplacesOldToken()
    {
        var oldToken = MagicLinkTokenGenerator.Generate();
        var now = DateTimeOffset.UtcNow;
        var (user, challenge) = await SeedChallengeAsync(
            ChallengeMethod.MagicLink, oldToken, now.AddMinutes(10), lastSentAt: now.AddSeconds(-61));
        // current config says Otp; the issued challenge must still get a link
        using var otpConfigClient = CreateClient("Otp", BaseUrl);

        using var resend = await otpConfigClient.PostAsJsonAsync("/auth/register/resend", new ResendRequest(user.Email));

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        var body = await resend.Content.ReadFromJsonAsync<ConfirmationRequiredResponse>();
        Assert.NotNull(body);
        Assert.Equal("magic_link", body.Method);
        Assert.Equal(challenge.Id, body.AttemptId);
        var newToken = TokenFor(user.Email);
        Assert.NotEqual(oldToken, newToken);
        using (var old = await ConfirmTokenAsync(oldToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        }

        using var fresh = await ConfirmTokenAsync(newToken);
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~Resend_UsesStoredMethodAndReplacesOldToken`
Expected: FAIL on `Assert.Equal("magic_link", body.Method)` (actual `"otp"`).

- [ ] **Step 3: Generate by stored method in `ResendAsync`**

Replace:

```csharp
        var code = OtpGenerator.Generate();
        challenge.SecretHash = new SecretHasher(options.Value.HmacKey).Hash(code);
```

with:

```csharp
        var secret = GenerateSecret(challenge.Method);
        challenge.SecretHash = new SecretHasher(options.Value.HmacKey).Hash(secret);
```

Replace:

```csharp
        await SendSecretAsync(user.Email, ChallengeMethod.Otp, code, ct);
        return new ResendResult.Sent(challenge.Id);
```

with:

```csharp
        await SendSecretAsync(user.Email, challenge.Method, secret, ct);
        return new ResendResult.Sent(challenge.Id, challenge.Method);
```

Replace the `Sent` record in `ResendResult` with:

```csharp
    public sealed record Sent(Guid AttemptId, ChallengeMethod Method) : ResendResult;
```

- [ ] **Step 4: Map the method in `RegistrationController.Resend`**

Replace:

```csharp
            ResendResult.Sent sent => Accepted(
                new ConfirmationRequiredResponse(true, "otp", sent.AttemptId, 600, 60)),
```

with:

```csharp
            ResendResult.Sent sent => Accepted(
                new ConfirmationRequiredResponse(true, sent.Method.ToContractName(), sent.AttemptId, 600, 60)),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all PASS, including every existing `ResendEndpointTests` case.

- [ ] **Step 6: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Registration/RegistrationService.cs src/FEDept.BackendCourse.GroupA1.Api.Template/Controllers/RegistrationController.cs tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/MagicLinkEndpointTests.cs
git commit -m "feat: resend uses the challenge's stored confirmation method"
```

---

### Task 7: Audit log for magic link without secrets

**Files:**
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/AuditLoggingTests.cs`

This task only adds a regression test; Task 4 already implemented the behavior.

- [ ] **Step 1: Capture links in the audit test fake**

In `AuditLoggingTests.cs`, replace the `CapturingEmailSender` class with:

```csharp
    private sealed class CapturingEmailSender : IEmailSender
    {
        public ConcurrentQueue<(string Email, string Code)> Messages { get; } = new();

        public ConcurrentQueue<(string Email, string Link)> Links { get; } = new();

        public Task SendOtpAsync(string email, string code, CancellationToken ct)
        {
            Messages.Enqueue((email, code));
            return Task.CompletedTask;
        }

        public Task SendMagicLinkAsync(string email, string link, CancellationToken ct)
        {
            Links.Enqueue((email, link));
            return Task.CompletedTask;
        }
    }
```

- [ ] **Step 2: Add the test after `RegistrationCodeSendAndConfirm_LogOutcomesWithoutSecrets`**

```csharp
    [Fact]
    public async Task MagicLinkSendAndConfirm_LogMethodWithoutTokenOrLink()
    {
        var provider = new CapturingLoggerProvider();
        var emailSender = new CapturingEmailSender();
        using var app = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:ConfirmationEnabled"] = "true",
                    ["Registration:ConfirmationMethod"] = "MagicLink",
                    ["Registration:MagicLinkBaseUrl"] = "http://localhost:3000/register/confirm",
                    ["Registration:HmacKey"] = HmacKey
                }));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IEmailSender>();
                services.AddSingleton<IEmailSender>(emailSender);
            });
            builder.ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddProvider(provider);
            });
        });
        using var client = app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        const string email = "audit-magic-link@example.com";
        using var pending = await client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, Password));
        var link = emailSender.Links.Single(item => item.Email == email).Link;
        var token = link[(link.IndexOf("token=", StringComparison.Ordinal) + "token=".Length)..];
        using var confirm = await client.PostAsJsonAsync("/auth/register/confirm", new { token });

        var logs = provider.Messages.ToArray();
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        Assert.Contains(logs, log => log.Contains("RegistrationCodeSent", StringComparison.Ordinal)
            && log.Contains(email, StringComparison.Ordinal)
            && log.Contains("Method=magic_link", StringComparison.Ordinal)
            && log.Contains("success", StringComparison.Ordinal));
        Assert.Contains(logs, log => log.Contains("RegistrationConfirm", StringComparison.Ordinal)
            && log.Contains(email, StringComparison.Ordinal)
            && log.Contains("success", StringComparison.Ordinal));
        Assert.All(logs, log =>
        {
            Assert.DoesNotContain(token, log, StringComparison.Ordinal);
            Assert.DoesNotContain(link, log, StringComparison.Ordinal);
            Assert.DoesNotContain(Password, log, StringComparison.Ordinal);
            Assert.DoesNotContain(HmacKey, log, StringComparison.Ordinal);
        });
    }
```

- [ ] **Step 3: Run tests**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~AuditLoggingTests`
Expected: PASS, 2 tests. If `Method=magic_link` is not found, check Task 4 Step 3 was applied.

- [ ] **Step 4: Commit**

```bash
git add tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/AuditLoggingTests.cs
git commit -m "test: magic link audit logs method without secrets"
```

---

### Task 8: Docs and local config

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/appsettings.Development.json`
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http`
- Modify: `docs/openapi.yaml`

- [ ] **Step 1: Development config**

In `appsettings.Development.json`, replace:

```json
  "Registration": {
    "ConfirmationEnabled": true,
    "HmacKey": "dev-local-hmac-key-change-me"
  },
```

with:

```json
  "Registration": {
    "ConfirmationEnabled": true,
    "ConfirmationMethod": "Otp",
    "MagicLinkBaseUrl": "http://localhost:3000/register/confirm",
    "HmacKey": "dev-local-hmac-key-change-me"
  },
```

- [ ] **Step 2: `.http` sample**

Append to `FEDept.BackendCourse.GroupA1.Api.Template.http`:

```http

### Confirm registration by magic link (copy the token from the link in Mailpit, http://localhost:8025)
POST {{FEDept.BackendCourse.GroupA1.Api.Template_HostAddress}}/auth/register/confirm
Content-Type: application/json

{
  "token": "token-from-magic-link"
}

###
```

- [ ] **Step 3: OpenAPI — register 202 description**

In `docs/openapi.yaml`, replace:

```yaml
          description: Confirmation is required; OTP was sent to the supplied email address.
```

with:

```yaml
          description: >-
            Confirmation is required; an OTP or a magic link (server setting) was sent to the
            supplied email address. The secret is never part of the response.
```

Also replace in the `/auth/register` description:

```yaml
        and sends an OTP when confirmation is enabled. A duplicate email returns
```

with:

```yaml
        and sends an OTP or a magic link when confirmation is enabled. A duplicate email returns
```

- [ ] **Step 4: OpenAPI — confirm operation**

Replace:

```yaml
      summary: Confirm registration with OTP
      description: >-
        Activates the pending account when the attempt ID and OTP match. The OTP
        expires after 600 seconds. Five failed code submissions consume the attempt.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConfirmRequest'
            example:
              attemptId: 2c4f09ad-610b-4c89-9c35-6df3ab02dbb9
              code: '012345'
```

with:

```yaml
      summary: Confirm registration with OTP or magic link token
      description: >-
        Activates the pending account. Send either the attempt ID and OTP, or the
        magic link token. Both expire after 600 seconds. Five failed code submissions
        consume an OTP attempt; a magic link token is single-use. Opening the link
        itself changes nothing; only this POST activates the account.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConfirmRequest'
            examples:
              otp:
                summary: OTP
                value:
                  attemptId: 2c4f09ad-610b-4c89-9c35-6df3ab02dbb9
                  code: '012345'
              magicLink:
                summary: Magic link token
                value:
                  token: q3Jx0dW9b6m1rQyZ4kFv8sT2nE7pL5cA0hG3uY6iO9w
```

- [ ] **Step 5: OpenAPI — schemas**

Replace the `ConfirmRequest` schema:

```yaml
    ConfirmRequest:
      type: object
      additionalProperties: false
      required: [attemptId, code]
      properties:
        attemptId:
          type: string
          format: uuid
          description: Confirmation attempt identifier returned by registration or resend.
        code:
          type: string
          pattern: '^[0-9]{6}$'
          description: Six-digit OTP sent to the account email address.
```

with:

```yaml
    ConfirmRequest:
      oneOf:
        - $ref: '#/components/schemas/ConfirmOtpRequest'
        - $ref: '#/components/schemas/ConfirmTokenRequest'
    ConfirmOtpRequest:
      type: object
      additionalProperties: false
      required: [attemptId, code]
      properties:
        attemptId:
          type: string
          format: uuid
          description: Confirmation attempt identifier returned by registration or resend.
        code:
          type: string
          pattern: '^[0-9]{6}$'
          description: Six-digit OTP sent to the account email address.
    ConfirmTokenRequest:
      type: object
      additionalProperties: false
      required: [token]
      properties:
        token:
          type: string
          pattern: '^[A-Za-z0-9_-]{43}$'
          description: One-time token from the magic link query string (`?token=`).
```

In `ConfirmationRequiredResponse`, replace:

```yaml
        method:
          type: string
          const: otp
```

with:

```yaml
        method:
          type: string
          enum: [otp, magic_link]
```

- [ ] **Step 6: Check YAML parses and the build is clean**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('docs/openapi.yaml'))" && dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: no output from Python, build succeeds.

- [ ] **Step 7: Commit**

```bash
git add src/FEDept.BackendCourse.GroupA1.Api.Template/appsettings.Development.json src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http docs/openapi.yaml
git commit -m "docs: document magic link confirmation"
```

---

### Task 9: Final verification

- [ ] **Step 1: Format check**

Run: `dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln --verify-no-changes`
Expected: exit code 0. If not, run `dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln`, review the diff, commit as `style: format`.

- [ ] **Step 2: Full test run**

Run: `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: all tests PASS, 0 failed.

- [ ] **Step 3: Manual smoke (optional, needs Docker Compose)**

Run: `docker compose up -d` and start the API with `Registration__ConfirmationMethod=MagicLink dotnet run --project src/FEDept.BackendCourse.GroupA1.Api.Template`.
Register via `POST /auth/register`, open Mailpit, copy the token from the link, `POST /auth/register/confirm {"token": "..."}`.
Expected: 202 with `method: "magic_link"`, then 200 with `status: "active"`.
