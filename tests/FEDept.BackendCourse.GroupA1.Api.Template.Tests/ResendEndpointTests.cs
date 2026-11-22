using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class ResendEndpointTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private const string HmacKey = "test-registration-hmac-key";
    private readonly RegistrationTestFactory _factory;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    public ResendEndpointTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _client = CreateClient(_emailSender);
    }

    [Fact]
    public async Task Resend_PendingEmailSendsNewCodeAndResetsChallenge()
    {
        var email = NewEmail();
        using var registration = await RegisterAsync(email);
        Assert.Equal(HttpStatusCode.Accepted, registration.StatusCode);
        var attemptId = (await registration.Content.ReadFromJsonAsync<ConfirmationRequiredResponse>())!.AttemptId;
        var oldCode = _emailSender.Messages.Single().Code;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var challenge = await db.RegistrationChallenges.SingleAsync(item => item.Id == attemptId);
            challenge.LastSentAt = DateTimeOffset.UtcNow.AddSeconds(-61);
            challenge.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            challenge.Attempts = 3;
            await db.SaveChangesAsync();
        }

        using var response = await _client.PostAsJsonAsync("/auth/register/resend", new ResendRequest(email.ToUpperInvariant()));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<ConfirmationRequiredResponse>())!;
        Assert.Equal(attemptId, body.AttemptId);
        Assert.Equal(600, body.ExpiresInSeconds);
        Assert.Equal(60, body.ResendAfterSeconds);
        Assert.Equal(2, _emailSender.Messages.Count);
        var newCode = _emailSender.Messages.Last().Code;
        Assert.NotEqual(oldCode, newCode);
        using (var scope = _factory.Services.CreateScope())
        {
            var challenge = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
                .RegistrationChallenges.SingleAsync(item => item.Id == attemptId);
            Assert.True(challenge.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(590));
            Assert.Equal(0, challenge.Attempts);
            Assert.False(new SecretHasher(HmacKey).Matches(oldCode, challenge.SecretHash));
            Assert.True(challenge.LastSentAt > DateTimeOffset.UtcNow.AddSeconds(-5));
        }

        using var oldCodeResponse = await ConfirmAsync(attemptId, oldCode);
        Assert.Equal(HttpStatusCode.BadRequest, oldCodeResponse.StatusCode);
        using var newCodeResponse = await ConfirmAsync(attemptId, newCode);
        Assert.Equal(HttpStatusCode.OK, newCodeResponse.StatusCode);
    }

    [Fact]
    public async Task Resend_SecondRequestWithinSixtySecondsReturnsTooManyRequests()
    {
        var email = NewEmail();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await SeedPendingAsync(db, email, DateTimeOffset.UtcNow.AddSeconds(-61));
        }

        using var first = await ResendAsync(email);
        using var second = await ResendAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        Assert.Single(_emailSender.Messages);
    }

    [Fact]
    public async Task Resend_UnknownOrActiveEmailReturnsNotFoundWithoutSending()
    {
        var activeEmail = NewEmail();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.Users.Add(new User
            {
                Id = Guid.NewGuid(),
                Email = activeEmail,
                PasswordHash = "hash",
                Status = UserStatus.Active,
                CreatedAt = now,
                UpdatedAt = now
            });
            await db.SaveChangesAsync();
        }

        using var unknown = await ResendAsync(NewEmail());
        using var active = await ResendAsync(activeEmail);

        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, active.StatusCode);
        Assert.Empty(_emailSender.Messages);
    }

    [Fact]
    public async Task Register_WhenEmailSendingFailsReturnsServiceUnavailableAndKeepsPendingRows()
    {
        using var throwingClient = CreateClient(new ThrowingEmailSender());
        var email = NewEmail();

        using var response = await throwingClient.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "abc12345"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.SingleAsync(item => item.Email == email);
        Assert.Equal(UserStatus.Pending, user.Status);
        Assert.Single(await db.RegistrationChallenges.Where(item => item.UserId == user.Id).ToListAsync());
    }

    [Fact]
    public async Task Resend_WhenEmailSendingFailsReturnsServiceUnavailableAndKeepsUpdatedChallenge()
    {
        var email = NewEmail();
        var challengeId = Guid.NewGuid();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var now = DateTimeOffset.UtcNow;
            var user = new User
            {
                Id = Guid.NewGuid(),
                Email = email,
                PasswordHash = "hash",
                Status = UserStatus.Pending,
                CreatedAt = now,
                UpdatedAt = now
            };
            db.Users.Add(user);
            db.RegistrationChallenges.Add(new RegistrationChallenge
            {
                Id = challengeId,
                UserId = user.Id,
                Method = ChallengeMethod.Otp,
                SecretHash = "old-hash",
                ExpiresAt = now.AddMinutes(10),
                Attempts = 2,
                LastSentAt = now.AddSeconds(-61)
            });
            await db.SaveChangesAsync();
        }

        using var throwingClient = CreateClient(new ThrowingEmailSender());
        using var response = await throwingClient.PostAsJsonAsync("/auth/register/resend", new ResendRequest(email));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        using var afterScope = _factory.Services.CreateScope();
        var challenge = await afterScope.ServiceProvider.GetRequiredService<AppDbContext>()
            .RegistrationChallenges.SingleAsync(item => item.Id == challengeId);
        Assert.Equal(0, challenge.Attempts);
        Assert.True(challenge.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(590));
        Assert.NotEqual("old-hash", challenge.SecretHash);
    }

    private HttpClient CreateClient(IEmailSender sender) => _factory.WithWebHostBuilder(builder =>
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
            services.AddSingleton<IEmailSender>(sender);
        });
    }).CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost")
    });

    private Task<HttpResponseMessage> RegisterAsync(string email) =>
        _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "abc12345"));

    private Task<HttpResponseMessage> ResendAsync(string email) =>
        _client.PostAsJsonAsync("/auth/register/resend", new ResendRequest(email));

    private Task<HttpResponseMessage> ConfirmAsync(Guid attemptId, string code) =>
        _client.PostAsJsonAsync("/auth/register/confirm", new ConfirmRequest(attemptId, code));

    private static async Task SeedPendingAsync(AppDbContext db, string email, DateTimeOffset lastSentAt)
    {
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            PasswordHash = "hash",
            Status = UserStatus.Pending,
            CreatedAt = now,
            UpdatedAt = now
        };
        db.Users.Add(user);
        db.RegistrationChallenges.Add(new RegistrationChallenge
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Method = ChallengeMethod.Otp,
            SecretHash = "old-hash",
            ExpiresAt = now.AddMinutes(10),
            Attempts = 2,
            LastSentAt = lastSentAt
        });
        await db.SaveChangesAsync();
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

    private sealed class ThrowingEmailSender : IEmailSender
    {
        public Task SendOtpAsync(string email, string code, CancellationToken ct) =>
            Task.FromException(new InvalidOperationException("SMTP unavailable"));
    }
}
