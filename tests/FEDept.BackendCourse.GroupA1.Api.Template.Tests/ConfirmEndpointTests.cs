using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class ConfirmEndpointTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private const string HmacKey = "test-registration-hmac-key";
    private readonly RegistrationTestFactory _factory;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    public ConfirmEndpointTests(RegistrationTestFactory factory)
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
    public async Task RegisterThenConfirm_ActivatesUser()
    {
        var email = NewEmail();
        using var registration = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, registration.StatusCode);
        var attemptId = await GetAttemptIdAsync(registration);
        var code = Assert.IsType<string>(_emailSender.LastCode);

        using var confirmation = await ConfirmAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.OK, confirmation.StatusCode);
        var user = await GetUserAsync(email);
        Assert.Equal(UserStatus.Active, user.Status);
        using var body = System.Text.Json.JsonDocument.Parse(await confirmation.Content.ReadAsStreamAsync());
        Assert.Equal(user.Id, body.RootElement.GetProperty("id").GetGuid());
        Assert.Equal(email, body.RootElement.GetProperty("email").GetString());
        Assert.Equal("active", body.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Register_CreatesOnePendingUserAndOneOpenChallenge()
    {
        var email = NewEmail();
        using var response = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var attemptId = await GetAttemptIdAsync(response);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var users = await db.Users.Where(user => user.Email == email).ToListAsync();
        Assert.Single(users);
        Assert.Equal(UserStatus.Pending, users[0].Status);
        var challenges = await db.RegistrationChallenges.Where(challenge => challenge.UserId == users[0].Id).ToListAsync();
        var challenge = Assert.Single(challenges);
        Assert.Equal(attemptId, challenge.Id);
        Assert.Null(challenge.ConsumedAt);
        Assert.Equal(0, challenge.Attempts);
        Assert.Equal(ChallengeMethod.Otp, challenge.Method);
    }

    [Fact]
    public async Task RegisterAgainForPendingEmail_ReturnsConflictWithoutSendingOrChangingChallenge()
    {
        var email = NewEmail();
        using var first = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        var attemptId = await GetAttemptIdAsync(first);
        var sentMessageCount = _emailSender.Messages.Count;
        RegistrationChallenge originalChallenge;
        using (var scope = _factory.Services.CreateScope())
        {
            originalChallenge = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
                .RegistrationChallenges.SingleAsync(challenge => challenge.Id == attemptId);
        }

        using var second = await RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal(sentMessageCount, _emailSender.Messages.Count);
        using var afterScope = _factory.Services.CreateScope();
        var unchangedChallenge = await afterScope.ServiceProvider.GetRequiredService<AppDbContext>()
            .RegistrationChallenges.SingleAsync(challenge => challenge.Id == attemptId);
        Assert.Equal(originalChallenge.SecretHash, unchangedChallenge.SecretHash);
        Assert.Equal(originalChallenge.Attempts, unchangedChallenge.Attempts);
        Assert.Equal(originalChallenge.ExpiresAt, unchangedChallenge.ExpiresAt);
        var users = await afterScope.ServiceProvider.GetRequiredService<AppDbContext>()
            .Users.Where(user => user.Email == email).ToListAsync();
        Assert.Single(users);
    }

    [Fact]
    public async Task Confirm_WrongCodeReturnsBadRequestAndIncrementsAttempts()
    {
        var (email, attemptId) = await RegisterPendingAsync();
        using var response = await ConfirmAsync(attemptId, "wrong-code");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(1, await GetChallengeAttemptsAsync(email));
    }

    [Fact]
    public async Task Confirm_FifthWrongCodeConsumesAttemptAndRejectsLaterCorrectCode()
    {
        var (email, attemptId) = await RegisterPendingAsync();
        for (var i = 0; i < 4; i++)
        {
            using var response = await ConfirmAsync(attemptId, "wrong-code");
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        using (var fifth = await ConfirmAsync(attemptId, "wrong-code"))
        {
            Assert.Equal((HttpStatusCode)429, fifth.StatusCode);
        }

        using var correct = await ConfirmAsync(attemptId, Assert.IsType<string>(_emailSender.LastCode));
        Assert.Equal(HttpStatusCode.BadRequest, correct.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var user = await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.SingleAsync(item => item.Email == email);
        var challenge = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .RegistrationChallenges.SingleAsync(item => item.UserId == user.Id);
        Assert.Equal(5, challenge.Attempts);
        Assert.NotNull(challenge.ConsumedAt);
    }

    [Fact]
    public async Task Confirm_ExpiredAttemptDoesNotIncrementAttempts()
    {
        var (user, challenge) = await SeedChallengeAsync(DateTimeOffset.UtcNow.AddSeconds(-1));
        using var response = await ConfirmAsync(challenge.Id, "wrong-code");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var saved = await db.RegistrationChallenges.SingleAsync(item => item.Id == challenge.Id);
        Assert.Equal(0, saved.Attempts);
        Assert.Null(saved.ConsumedAt);
        Assert.Equal(UserStatus.Pending, (await db.Users.SingleAsync(item => item.Id == user.Id)).Status);
    }

    [Fact]
    public async Task Confirm_UnknownAndConsumedAttemptIdsReturnBadRequest()
    {
        using (var unknown = await ConfirmAsync(Guid.NewGuid(), "123456"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        }

        var (_, consumed) = await SeedChallengeAsync(DateTimeOffset.UtcNow.AddMinutes(10), DateTimeOffset.UtcNow);
        using var response = await ConfirmAsync(consumed.Id, "123456");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private async Task<(string Email, Guid AttemptId)> RegisterPendingAsync()
    {
        var email = NewEmail();
        using var response = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        return (email, await GetAttemptIdAsync(response));
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

    private async Task<User> GetUserAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.SingleAsync(user => user.Email == email);
    }

    private async Task<int> GetChallengeAttemptsAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.SingleAsync(item => item.Email == email);
        return await db.RegistrationChallenges.Where(item => item.UserId == user.Id).Select(item => item.Attempts).SingleAsync();
    }

    private async Task<(User User, RegistrationChallenge Challenge)> SeedChallengeAsync(
        DateTimeOffset expiresAt, DateTimeOffset? consumedAt = null)
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
            Method = ChallengeMethod.Otp,
            SecretHash = new SecretHasher(HmacKey).Hash("654321"),
            ExpiresAt = expiresAt,
            Attempts = 0,
            LastSentAt = now,
            ConsumedAt = consumedAt
        };
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Users.Add(user);
        db.RegistrationChallenges.Add(challenge);
        await db.SaveChangesAsync();
        return (user, challenge);
    }

    private static string NewEmail() => $"{Guid.NewGuid():N}@example.com";

    public void Dispose() => _client.Dispose();

    private sealed class CapturingEmailSender : IEmailSender
    {
        public string? LastCode { get; private set; }
        public ConcurrentQueue<(string Email, string Code)> Messages { get; } = new();

        public Task SendOtpAsync(string email, string code, CancellationToken ct)
        {
            LastCode = code;
            Messages.Enqueue((email, code));
            return Task.CompletedTask;
        }
    }
}
