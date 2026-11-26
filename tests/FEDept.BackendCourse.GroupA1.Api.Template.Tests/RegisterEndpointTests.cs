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
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class RegisterEndpointTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private readonly RegistrationTestFactory _factory;
    private readonly HttpClient _client;
    private readonly CapturingEmailSender _emailSender = new();

    public RegisterEndpointTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _client = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:ConfirmationEnabled"] = "false"
                }));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IEmailSender>();
                services.AddSingleton<IEmailSender>(_emailSender);
            });
        }).CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
    }

    [Fact]
    public async Task Register_ValidRequest_ReturnsActiveWithNormalizedEmailAndNoSecrets()
    {
        using var response = await RegisterAsync("  User@Example.COM ", "abc12345");
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = body.RootElement;

        Assert.Equal("active", root.GetProperty("status").GetString());
        Assert.Equal("user@example.com", root.GetProperty("email").GetString());
        Assert.Equal(new[] { "email", "id", "status" }, root.EnumerateObject()
            .Select(property => property.Name)
            .OrderBy(name => name));
        Assert.DoesNotContain(root.EnumerateObject(), property =>
            property.Name.Contains("password", StringComparison.OrdinalIgnoreCase)
            || property.Name.Contains("hash", StringComparison.OrdinalIgnoreCase)
            || property.Name.Contains("token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Register_ExistingActiveEmail_ReturnsConflictWithoutAccountDetails()
    {
        const string email = "taken@example.com";
        using var first = await RegisterAsync(email, "abc12345");
        using var second = await RegisterAsync(email, "abc12345");
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        using var firstBody = await JsonDocument.ParseAsync(await first.Content.ReadAsStreamAsync());
        var accountId = firstBody.RootElement.GetProperty("id").GetGuid();
        using var secondBody = await JsonDocument.ParseAsync(await second.Content.ReadAsStreamAsync());
        var root = secondBody.RootElement;
        Assert.Equal((int)HttpStatusCode.Conflict, root.GetProperty("status").GetInt32());
        Assert.False(root.TryGetProperty("id", out _));
        Assert.False(root.TryGetProperty("email", out _));
        Assert.DoesNotContain(accountId.ToString(), root.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(email, root.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Register_ConcurrentDuplicateRequests_ReturnExactlyOneCreatedAndOneConflict()
    {
        var responses = await Task.WhenAll(
            RegisterAsync("parallel@example.com", "abc12345"),
            RegisterAsync("parallel@example.com", "abc12345"));
        using var first = responses[0];
        using var second = responses[1];

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Created));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Conflict));
        Assert.DoesNotContain(responses, response => response.StatusCode == HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task Register_PendingEmail_ReturnsConflictWithoutSendingEmailOrChangingChallenge()
    {
        var userId = Guid.NewGuid();
        var email = $"{Guid.NewGuid():N}@example.com";
        var challenge = new RegistrationChallenge
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Method = ChallengeMethod.Otp,
            SecretHash = "not-a-real-hash",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
            Attempts = 2,
            LastSentAt = DateTimeOffset.UtcNow,
            ConsumedAt = null
        };
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.Users.Add(new User
            {
                Id = userId,
                Email = email,
                PasswordHash = "not-a-real-hash",
                Status = UserStatus.Pending,
                CreatedAt = now,
                UpdatedAt = now
            });
            db.RegistrationChallenges.Add(challenge);
            await db.SaveChangesAsync();
        }

        using var response = await RegisterAsync(email, "abc12345");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Empty(_emailSender.Messages);
        using var afterScope = _factory.Services.CreateScope();
        var savedChallenge = await afterScope.ServiceProvider.GetRequiredService<AppDbContext>()
            .RegistrationChallenges.SingleAsync(item => item.Id == challenge.Id);
        Assert.Equal(challenge.SecretHash, savedChallenge.SecretHash);
        Assert.Equal(challenge.Attempts, savedChallenge.Attempts);
        Assert.Equal(challenge.ExpiresAt, savedChallenge.ExpiresAt);
    }

    [Fact]
    public async Task Register_EdgeSpacePassword_PreservesSpacesAndSucceeds()
    {
        using var response = await RegisterAsync("spaces@example.com", " abc123 ");
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.SingleAsync(user => user.Email == "spaces@example.com");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.True(BCrypt.Net.BCrypt.Verify(" abc123 ", user.PasswordHash));
    }

    private Task<HttpResponseMessage> RegisterAsync(string email, string password) =>
        _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, password));

    public void Dispose() => _client.Dispose();

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
}
