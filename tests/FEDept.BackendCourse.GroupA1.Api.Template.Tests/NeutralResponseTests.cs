using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
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

public sealed class NeutralResponseTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private const string HmacKey = "test-registration-hmac-key";
    private readonly RegistrationTestFactory _factory;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    public NeutralResponseTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _client = factory.WithWebHostBuilder(builder =>
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
                services.AddSingleton<IEmailSender>(_emailSender);
            });
        }).CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
    }

    [Fact]
    public async Task Register_ActiveEmailReturnsPersistedDecoyWithIndistinguishableConfirmFailure()
    {
        var activeEmail = NewEmail();
        var activeUser = await SeedUserAsync(activeEmail, UserStatus.Active);
        using var takenResponse = await RegisterAsync(activeEmail);
        Assert.Equal(HttpStatusCode.Accepted, takenResponse.StatusCode);
        var decoyId = await GetAttemptIdAsync(takenResponse);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var decoy = await db.RegistrationChallenges.SingleAsync(item => item.Id == decoyId);
        Assert.Equal(activeUser.Id, decoy.UserId);
        Assert.Equal(ChallengeMethod.Otp, decoy.Method);
        Assert.Equal(0, decoy.Attempts);
        Assert.Null(decoy.ConsumedAt);
        Assert.DoesNotContain(_emailSender.Messages, message => message.Email == activeEmail);

        var genuineEmail = NewEmail();
        using var genuineResponse = await RegisterAsync(genuineEmail);
        var genuineId = await GetAttemptIdAsync(genuineResponse);
        using var decoyConfirm = await ConfirmAsync(decoyId, "123456");
        using var genuineWrongCodeConfirm = await ConfirmAsync(genuineId, "wrong-code");

        Assert.Equal(HttpStatusCode.BadRequest, decoyConfirm.StatusCode);
        Assert.Equal(genuineWrongCodeConfirm.StatusCode, decoyConfirm.StatusCode);
        Assert.Equal(await GetConfirmErrorBodyAsync(genuineWrongCodeConfirm),
            await GetConfirmErrorBodyAsync(decoyConfirm));
    }

    [Fact]
    public async Task Register_PendingEmailResendsWorkingCodeAndReusesChallenge()
    {
        var email = NewEmail();
        using var firstResponse = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, firstResponse.StatusCode);
        var firstAttemptId = await GetAttemptIdAsync(firstResponse);
        Assert.Single(_emailSender.Messages, message => message.Email == email);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var wrongConfirmation = await ConfirmAsync(firstAttemptId, "wrong-code");
            Assert.Equal(attempt == 4 ? (HttpStatusCode)429 : HttpStatusCode.BadRequest, wrongConfirmation.StatusCode);
        }

        using var beforeResendScope = _factory.Services.CreateScope();
        var beforeResendDb = beforeResendScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var beforeResendChallenge = await beforeResendDb.RegistrationChallenges.SingleAsync(item => item.Id == firstAttemptId);
        Assert.NotNull(beforeResendChallenge.ConsumedAt);
        var previousLastSentAt = beforeResendChallenge.LastSentAt;

        using var secondResponse = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, secondResponse.StatusCode);
        var secondAttemptId = await GetAttemptIdAsync(secondResponse);
        var resentCode = _emailSender.Messages.Last(message => message.Email == email).Code;

        Assert.Equal(firstAttemptId, secondAttemptId);
        using (var afterResendScope = _factory.Services.CreateScope())
        {
            var afterResendDb = afterResendScope.ServiceProvider.GetRequiredService<AppDbContext>();
            var updatedChallenge = await afterResendDb.RegistrationChallenges.SingleAsync(item => item.Id == secondAttemptId);
            Assert.Equal(0, updatedChallenge.Attempts);
            Assert.Null(updatedChallenge.ConsumedAt);
            Assert.True(updatedChallenge.LastSentAt >= previousLastSentAt);
            Assert.True(updatedChallenge.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(590));
        }

        using var confirmation = await ConfirmAsync(secondAttemptId, resentCode);
        Assert.Equal(HttpStatusCode.OK, confirmation.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.SingleAsync(item => item.Email == email);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.Single(await db.RegistrationChallenges.Where(item => item.UserId == user.Id).ToListAsync());
        Assert.Equal(2, _emailSender.Messages.Count(message => message.Email == email));
    }

    private async Task<User> SeedUserAsync(string email, UserStatus status)
    {
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            PasswordHash = "not-a-real-hash",
            Status = status,
            CreatedAt = now,
            UpdatedAt = now
        };
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    private Task<HttpResponseMessage> RegisterAsync(string email) =>
        _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "abc12345"));

    private Task<HttpResponseMessage> ConfirmAsync(Guid attemptId, string code) =>
        _client.PostAsJsonAsync("/auth/register/confirm", new { attemptId, code });

    private static async Task<Guid> GetAttemptIdAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<ConfirmationRequiredResponse>();
        Assert.NotNull(body);
        return body.AttemptId;
    }

    private static async Task<string> GetConfirmErrorBodyAsync(HttpResponseMessage response)
    {
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        body.Remove("traceId");
        return body.ToJsonString();
    }

    private static string NewEmail() => $"{Guid.NewGuid():N}@example.com";

    public void Dispose() => _client.Dispose();

    private sealed class CapturingEmailSender : IEmailSender
    {
        public ConcurrentQueue<(string Email, string Code)> Messages { get; } = new();

        public Task SendOtpAsync(string email, string code, CancellationToken ct)
        {
            Messages.Enqueue((email, code));
            return Task.CompletedTask;
        }
    }
}
