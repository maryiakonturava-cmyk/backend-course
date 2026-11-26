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
