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
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class AuthAuditTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private (WebApplicationFactory<Program> App, CapturingLoggerProvider Logs, CapturingLoginEmailSender Sender) Create(bool challenge, string method = "Otp")
    {
        var logs = new CapturingLoggerProvider();
        var sender = new CapturingLoginEmailSender();
        var app = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Login:ConfirmationEnabled"] = challenge ? "true" : "false",
                ["Login:ConfirmationMethod"] = method,
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
        var auditLines = lines.Where(line => line.Contains("EventName=", StringComparison.Ordinal)).ToArray();
        Assert.All(auditLines, line => Assert.Contains("RequestId:", line, StringComparison.Ordinal));
        AssertNoSecrets(lines, email, unknownEmail, Password, "wrong password 1", access, refresh);
    }

    [Theory]
    [InlineData("Otp")]
    [InlineData("MagicLink")]
    public async Task Challenge_LogsLifecycleWithoutCode(string method)
    {
        var (app, logs, sender) = Create(challenge: true, method);
        using var _app = app;
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);

        using var login = await LoginAsync(client, email);
        var attemptId = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("attemptId").GetGuid();
        string? code = null;
        string? token = null;
        string? tokenSecret = null;
        if (method == "Otp")
        {
            code = sender.LastFor(email);
        }
        else
        {
            var link = sender.LastFor(email);
            token = link[(link.IndexOf("#token=", StringComparison.Ordinal) + 7)..];
            tokenSecret = token[(token.IndexOf('.') + 1)..];
        }

        using var wrong = method == "Otp"
            ? await client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code = code == "000000" ? "111111" : "000000" })
            : await client.PostAsJsonAsync("/auth/login/confirm", new { token = $"{attemptId}.{(tokenSecret![0] == 'A' ? 'B' : 'A')}{tokenSecret[1..]}" });
        using var confirm = method == "Otp"
            ? await client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code })
            : await client.PostAsJsonAsync("/auth/login/confirm", new { token });

        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
        var lines = logs.Messages.Where(line => line.Contains("EventName=LoginChallenge", StringComparison.Ordinal)).ToArray();
        var contractMethod = method == "Otp" ? "otp" : "magic_link";
        foreach (var outcome in new[] { "created", "wrong_entry", "confirmed" })
        {
            Assert.Contains(lines, line => line.Contains($"Outcome={outcome}", StringComparison.Ordinal)
                && line.Contains($"AttemptId={attemptId}", StringComparison.Ordinal)
                && line.Contains($"Method={contractMethod}", StringComparison.Ordinal));
        }

        var secrets = new List<string> { email, Password, CookieValue(confirm, "access_token"), CookieValue(confirm, "refresh_token") };
        if (code is not null)
        {
            secrets.Add(code);
        }

        if (token is not null)
        {
            secrets.Add(token);
            secrets.Add(tokenSecret!);
        }

        AssertNoSecrets(logs.Messages, secrets.ToArray());
    }

    [Fact]
    public void EmailRef_IsDeterministicKeyedAndDoesNotContainEmail()
    {
        const string email = "member@example.com";
        var audit = CreateAudit(new string('k', 32));
        var otherKeyAudit = CreateAudit(new string('x', 32));

        var first = audit.EmailRef(email);
        var second = audit.EmailRef(email);
        var otherKey = otherKeyAudit.EmailRef(email);

        Assert.Equal(first, second);
        Assert.NotEqual(first, otherKey);
        Assert.DoesNotContain(email, first);
    }

    [Fact]
    public async Task OtpChallenge_MagicLinkShapeIsRejectedWithoutAttemptOrWrongEntryAudit()
    {
        var (app, logs, _) = Create(challenge: true);
        using var _app = app;
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);

        using var login = await LoginAsync(client, email);
        var attemptId = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("attemptId").GetGuid();
        using var response = await client.PostAsJsonAsync("/auth/login/confirm", new { token = $"{attemptId}.{new string('A', 43)}" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_challenge", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        var challenge = await GetChallengeAsync(app.Services, attemptId);
        Assert.Equal(0, challenge.Attempts);
        Assert.Null(challenge.ConsumedAt);

        var attemptLines = logs.Messages.Where(line => line.Contains("EventName=LoginChallenge", StringComparison.Ordinal)
            && line.Contains($"AttemptId={attemptId}", StringComparison.Ordinal)).ToArray();
        Assert.Contains(attemptLines, line => line.Contains("Outcome=rejected", StringComparison.Ordinal));
        Assert.DoesNotContain(attemptLines, line => line.Contains("Outcome=wrong_entry", StringComparison.Ordinal));
    }

    private static AuthAudit CreateAudit(string key) => new(
        NullLogger<AuthAudit>.Instance,
        Options.Create(new LoginOptions { AuditHmacKey = key }));
}
