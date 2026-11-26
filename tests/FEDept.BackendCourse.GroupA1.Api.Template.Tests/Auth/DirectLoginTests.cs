using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class DirectLoginTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    [Fact]
    public async Task Login_ActiveUser_Returns204WithBothCookiesAndNoBody()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);

        using var response = await LoginAsync(client, email);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        AssertSessionCookies(response);
    }

    [Fact]
    public async Task Login_NormalizesEmail()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);

        using var response = await LoginAsync(client, $"  {email.ToUpperInvariant()} ");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Login_DoesNotTrimPassword()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);

        using var response = await LoginAsync(client, email, Password.Trim());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_UnknownWrongPasswordAndInactiveStatuses_ReturnIdenticalNeutral401()
    {
        using var client = CreateClient(factory);
        var active = NewEmail();
        await CreateUserAsync(factory.Services, active);
        var attempts = new List<(string Email, string Password)> { (NewEmail(), Password), (active, "wrong password 1") };
        foreach (var status in new[] { UserStatus.Pending, UserStatus.Blocked, UserStatus.Deleting, UserStatus.Deleted })
        {
            var email = NewEmail();
            await CreateUserAsync(factory.Services, email, status);
            attempts.Add((email, Password));
        }

        var bodies = new List<string>();
        foreach (var (email, password) in attempts)
        {
            using var response = await LoginAsync(client, email, password);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(SetCookies(response));
            bodies.Add(await response.Content.ReadAsStringAsync());
        }

        Assert.Single(bodies.Distinct());
        using var body = JsonDocument.Parse(bodies[0]);
        Assert.Equal("invalid_credentials", body.RootElement.GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("{\"password\":\"x\"}")]
    [InlineData("{\"email\":\"not-an-email\",\"password\":\"x\"}")]
    [InlineData("{\"email\":\"user@example.com\"}")]
    public async Task Login_InvalidFormat_Returns400(string json)
    {
        using var client = CreateClient(factory);

        using var response = await client.PostAsync("/auth/login", new StringContent(json, System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_SixthCheckAfterFiveFailures_Returns429EvenWithCorrectPassword()
    {
        using var client = CreateClient(factory);
        var email = NewEmail();
        await CreateUserAsync(factory.Services, email);
        for (var i = 0; i < 5; i++)
        {
            using var failed = await LoginAsync(client, email, "wrong password 1");
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        using var response = await LoginAsync(client, email);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(response.Headers.RetryAfter is not null);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("retryAfterSeconds").GetInt32() > 0);
    }

    [Fact]
    public async Task Login_ThirtyFirstRequestPerMinuteFromOneIp_Returns429()
    {
        using var app = factory.WithSettings(new Dictionary<string, string?> { ["Login:LoginPermitPerMinute"] = "30" });
        using var client = CreateClient(app);
        for (var i = 0; i < 30; i++)
        {
            using var allowed = await client.PostAsJsonAsync("/auth/login", new { password = "x" });
            Assert.Equal(HttpStatusCode.BadRequest, allowed.StatusCode);
        }

        using var response = await client.PostAsJsonAsync("/auth/login", new { password = "x" });

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(response.Headers.RetryAfter is not null);
    }
}
