using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class RegisterEndpointTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private readonly RegistrationTestFactory _factory;
    private readonly HttpClient _client;

    public RegisterEndpointTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _client = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:ConfirmationEnabled"] = "false"
                })))
            .CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
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
    public async Task Register_ExistingEmail_ReturnsNeutralAcceptedResponse()
    {
        using var first = await RegisterAsync("taken@example.com", "abc12345");
        using var second = await RegisterAsync("taken@example.com", "abc12345");
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        using var body = await JsonDocument.ParseAsync(await second.Content.ReadAsStreamAsync());
        var root = body.RootElement;

        Assert.True(root.GetProperty("confirmationRequired").GetBoolean());
        Assert.Equal("otp", root.GetProperty("method").GetString());
        Assert.Equal(600, root.GetProperty("expiresInSeconds").GetInt32());
        Assert.Equal(60, root.GetProperty("resendAfterSeconds").GetInt32());
        Assert.DoesNotContain("id", root.EnumerateObject().Select(property => property.Name));
        Assert.DoesNotContain("email", root.EnumerateObject().Select(property => property.Name));
        Assert.DoesNotContain("status", root.EnumerateObject().Select(property => property.Name));
    }

    [Fact]
    public async Task Register_ConcurrentDuplicateRequests_ReturnExactlyOneCreatedAndOneAccepted()
    {
        var responses = await Task.WhenAll(
            RegisterAsync("parallel@example.com", "abc12345"),
            RegisterAsync("parallel@example.com", "abc12345"));
        using var first = responses[0];
        using var second = responses[1];

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Created));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Accepted));
        Assert.DoesNotContain(responses, response => response.StatusCode == HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task Register_PendingEmail_ReturnsNeutralAcceptedResponse()
    {
        var userId = Guid.NewGuid();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Users.Add(new User
            {
                Id = userId,
                Email = "pending@example.com",
                PasswordHash = "not-a-real-hash",
                Status = UserStatus.Pending,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        using var response = await RegisterAsync("pending@example.com", "abc12345");
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var root = body.RootElement;

        Assert.True(root.GetProperty("confirmationRequired").GetBoolean());
        Assert.NotEqual(userId, root.GetProperty("attemptId").GetGuid());
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
}
