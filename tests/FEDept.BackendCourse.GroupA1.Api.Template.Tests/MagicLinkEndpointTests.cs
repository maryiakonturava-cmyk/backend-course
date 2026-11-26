using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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

    private Task<HttpResponseMessage> RegisterAsync(string email) =>
        _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "abc12345"));

    private string TokenFor(string email)
    {
        var link = _emailSender.Links.Last(item => item.Email == email).Link;
        Assert.StartsWith($"{BaseUrl}?token=", link, StringComparison.Ordinal);
        return link[$"{BaseUrl}?token=".Length..];
    }

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

    private static string NewEmail() => $"{Guid.NewGuid():N}@example.com";

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
