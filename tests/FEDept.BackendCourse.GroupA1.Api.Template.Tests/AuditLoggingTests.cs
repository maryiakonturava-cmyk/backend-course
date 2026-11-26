using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class AuditLoggingTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private const string Password = "audit-secret-password-84";
    private const string HmacKey = "audit-test-hmac-key";

    [Fact]
    public async Task RegistrationCodeSendAndConfirm_LogOutcomesWithoutSecrets()
    {
        var provider = new CapturingLoggerProvider();
        var emailSender = new CapturingEmailSender();
        using var app = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:ConfirmationEnabled"] = "true",
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

        const string takenEmail = "audit-taken@example.com";
        using var created = await client.PostAsJsonAsync("/auth/register", new RegisterRequest(takenEmail, Password));
        using var duplicate = await client.PostAsJsonAsync("/auth/register", new RegisterRequest(takenEmail, Password));
        using var pending = await client.PostAsJsonAsync("/auth/register", new RegisterRequest("audit-confirm@example.com", Password));
        var pendingBody = await pending.Content.ReadFromJsonAsync<ConfirmationRequiredResponse>();
        Assert.NotNull(pendingBody);
        var code = emailSender.Messages.Last().Code;
        using var badConfirm = await client.PostAsJsonAsync("/auth/register/confirm", new ConfirmRequest(pendingBody.AttemptId, "wrong-code"));
        using var goodConfirm = await client.PostAsJsonAsync("/auth/register/confirm", new ConfirmRequest(pendingBody.AttemptId, code));

        var logs = provider.Messages.ToArray();
        Assert.Equal(HttpStatusCode.Accepted, created.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, pending.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, badConfirm.StatusCode);
        Assert.Equal(HttpStatusCode.OK, goodConfirm.StatusCode);
        Assert.Contains(logs, log => log.Contains("RegistrationAttempt", StringComparison.Ordinal)
            && log.Contains("audit-taken@example.com", StringComparison.Ordinal)
            && log.Contains("success", StringComparison.Ordinal));
        Assert.Contains(logs, log => log.Contains("RegistrationAttempt", StringComparison.Ordinal)
            && log.Contains("audit-taken@example.com", StringComparison.Ordinal)
            && log.Contains("failure", StringComparison.Ordinal));
        Assert.Contains(logs, log => log.Contains("RegistrationCodeSent", StringComparison.Ordinal)
            && log.Contains("audit-confirm@example.com", StringComparison.Ordinal)
            && log.Contains("success", StringComparison.Ordinal));
        Assert.Contains(logs, log => log.Contains("RegistrationConfirm", StringComparison.Ordinal)
            && log.Contains("audit-confirm@example.com", StringComparison.Ordinal)
            && log.Contains("failure", StringComparison.Ordinal));
        Assert.Contains(logs, log => log.Contains("RegistrationConfirm", StringComparison.Ordinal)
            && log.Contains("audit-confirm@example.com", StringComparison.Ordinal)
            && log.Contains("success", StringComparison.Ordinal));
        Assert.All(logs, log =>
        {
            Assert.DoesNotContain(Password, log, StringComparison.Ordinal);
            Assert.DoesNotContain(code, log, StringComparison.Ordinal);
            Assert.DoesNotContain(HmacKey, log, StringComparison.Ordinal);
            Assert.DoesNotContain("password_hash", log, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("secret_hash", log, StringComparison.OrdinalIgnoreCase);
        });
    }

    private sealed class CapturingEmailSender : IEmailSender
    {
        public ConcurrentQueue<(string Email, string Code)> Messages { get; } = new();

        public Task SendOtpAsync(string email, string code, CancellationToken ct)
        {
            Messages.Enqueue((email, code));
            return Task.CompletedTask;
        }

        public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) =>
            new CapturingLogger(Messages, categoryName == typeof(RegistrationService).FullName);

        public void Dispose() { }
    }

    private sealed class CapturingLogger(ConcurrentQueue<string> messages, bool enabled) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => enabled;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
    }
}
