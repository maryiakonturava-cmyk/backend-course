using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class SessionTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private async Task<(Guid UserId, HttpResponseMessage Login)> SignInAsync(HttpClient client)
    {
        var email = NewEmail();
        var userId = await CreateUserAsync(factory.Services, email);
        var login = await LoginAsync(client, email);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return (userId, login);
    }

    private static async Task AssertInvalidSessionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(SetCookies(response));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_session", body.GetProperty("code").GetString());
    }

    private WebApplicationFactory<Program> WithProtectedRoute(Dictionary<string, string?>? settings = null) =>
        factory.WithSettings(settings ?? new Dictionary<string, string?>(), services =>
            services.AddControllers().AddApplicationPart(typeof(ProtectedTestController).Assembly));

    private static Dictionary<string, string?> DatabaseUnavailableSettings() => new()
    {
        ["ConnectionStrings:Default"] = "Host=127.0.0.1;Port=1;Database=none;Username=none;Password=none;Timeout=2",
        ["Database:ApplyMigrations"] = "false"
    };

    private static Task<HttpResponseMessage> GetProtectedAsync(HttpClient client, string? cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/test/protected");
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return client.SendAsync(request);
    }

    [Fact]
    public async Task Access_ValidCookie_PassesOnlyTheUserId()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var email = NewEmail();
        var userId = await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);

        using var response = await GetProtectedAsync(client, $"access_token={CookieValue(login, "access_token")}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(userId.ToString(), body.GetProperty("userId").GetString());
    }

    [Fact]
    public async Task Access_MissingCookie_Returns401()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);

        using var response = await GetProtectedAsync(client, null);

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Access_RefreshTokenAsAccess_Returns401()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);

        using var response = await GetProtectedAsync(client, $"access_token={CookieValue(login, "refresh_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Access_ExpiredToken_Returns401()
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var userId = await CreateUserAsync(app.Services, NewEmail());
        var expired = app.Services.GetRequiredService<JwtTokenService>().Issue(userId, DateTimeOffset.UtcNow.AddMinutes(-16));

        using var response = await GetProtectedAsync(client, $"access_token={expired.AccessToken}");

        await AssertInvalidSessionAsync(response);
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    [InlineData(UserStatus.Deleted)]
    public async Task Access_InactiveUser_Returns401(UserStatus status)
    {
        using var app = WithProtectedRoute();
        using var client = CreateClient(app);
        var email = NewEmail();
        var userId = await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);
        await SetStatusAsync(app.Services, userId, status);

        using var response = await GetProtectedAsync(client, $"access_token={CookieValue(login, "access_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_ValidCookie_Returns204WithNewPair()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={CookieValue(login, "refresh_token")}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        AssertSessionCookies(response);
    }

    [Fact]
    public async Task Refresh_UsedTokenStaysValidUntilExp()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);
        var cookie = $"refresh_token={CookieValue(login, "refresh_token")}";

        using var first = await PostWithCookieAsync(client, "/auth/refresh", cookie);
        using var second = await PostWithCookieAsync(client, "/auth/refresh", cookie);

        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
    }

    [Fact]
    public async Task Refresh_MissingCookie_Returns401()
    {
        using var client = CreateClient(factory);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", null);

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_ValidTokenForMissingUser_Returns401()
    {
        using var client = CreateClient(factory);
        var token = factory.Services.GetRequiredService<JwtTokenService>().Issue(Guid.NewGuid()).RefreshToken;

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={token}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_AccessTokenInRefreshCookie_Returns401()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={CookieValue(login, "access_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_TokenOutsideTheCookie_IsIgnored()
    {
        using var client = CreateClient(factory);
        var (_, login) = await SignInAsync(client);
        var token = CookieValue(login, "refresh_token");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/auth/refresh?refresh_token={token}")
        {
            Content = JsonContent.Create(new { refresh_token = token })
        };
        request.Headers.Add("Authorization", $"Bearer {token}");

        using var response = await client.SendAsync(request);

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_ExpiredToken_Returns401()
    {
        using var client = CreateClient(factory);
        var userId = await CreateUserAsync(factory.Services, NewEmail());
        var expired = factory.Services.GetRequiredService<JwtTokenService>().Issue(userId, DateTimeOffset.UtcNow.AddDays(-31));

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={expired.RefreshToken}");

        await AssertInvalidSessionAsync(response);
    }

    [Theory]
    [InlineData(UserStatus.Pending)]
    [InlineData(UserStatus.Blocked)]
    [InlineData(UserStatus.Deleting)]
    [InlineData(UserStatus.Deleted)]
    public async Task Refresh_InactiveUser_Returns401(UserStatus status)
    {
        using var client = CreateClient(factory);
        var (userId, login) = await SignInAsync(client);
        await SetStatusAsync(factory.Services, userId, status);

        using var response = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={CookieValue(login, "refresh_token")}");

        await AssertInvalidSessionAsync(response);
    }

    [Fact]
    public async Task Refresh_ThirtyFirstRequestPerMinuteFromOneIp_Returns429()
    {
        using var app = factory.WithSettings(new Dictionary<string, string?> { ["Login:RefreshPermitPerMinute"] = "30" });
        using var client = CreateClient(app);
        for (var i = 0; i < 30; i++)
        {
            using var allowed = await PostWithCookieAsync(client, "/auth/refresh", null);
            Assert.Equal(HttpStatusCode.Unauthorized, allowed.StatusCode);
        }

        using var response = await PostWithCookieAsync(client, "/auth/refresh", null);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("access_token=garbage; refresh_token=garbage")]
    public async Task Logout_AlwaysReturns204AndClearsBothCookies(string? cookie)
    {
        using var client = CreateClient(factory);

        using var response = await PostWithCookieAsync(client, "/auth/logout", cookie);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        var access = SetCookie(response, "access_token").ToLowerInvariant();
        var refresh = SetCookie(response, "refresh_token").ToLowerInvariant();
        Assert.StartsWith("access_token=;", access, StringComparison.Ordinal);
        Assert.StartsWith("refresh_token=;", refresh, StringComparison.Ordinal);
        Assert.Contains("max-age=0", access, StringComparison.Ordinal);
        Assert.Contains("max-age=0", refresh, StringComparison.Ordinal);
        Assert.Contains("path=/;", access, StringComparison.Ordinal);
        Assert.Contains("path=/auth/refresh", refresh, StringComparison.Ordinal);
        Assert.All(new[] { access, refresh }, header =>
        {
            Assert.Contains("secure", header, StringComparison.Ordinal);
            Assert.Contains("samesite=strict", header, StringComparison.Ordinal);
            Assert.DoesNotContain("domain=", header, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Logout_ValidAccessCookieAndUnavailableDatabase_ClearsBothCookies()
    {
        using var app = factory.WithSettings(DatabaseUnavailableSettings());
        using var client = CreateClient(app);
        var token = app.Services.GetRequiredService<JwtTokenService>().Issue(Guid.NewGuid()).AccessToken;

        using var response = await PostWithCookieAsync(client, "/auth/logout", $"access_token={token}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        Assert.StartsWith("access_token=;", SetCookie(response, "access_token"), StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("refresh_token=;", SetCookie(response, "refresh_token"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Access_DatabaseUnavailable_Returns503()
    {
        using var app = WithProtectedRoute(DatabaseUnavailableSettings());
        using var client = CreateClient(app);
        var token = app.Services.GetRequiredService<JwtTokenService>().Issue(Guid.NewGuid()).AccessToken;

        using var response = await GetProtectedAsync(client, $"access_token={token}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task DatabaseUnavailable_LoginAndRefreshReturn503()
    {
        using var app = factory.WithSettings(DatabaseUnavailableSettings());
        using var client = CreateClient(app);
        var token = app.Services.GetRequiredService<JwtTokenService>().Issue(Guid.NewGuid()).RefreshToken;

        using var login = await LoginAsync(client, NewEmail());
        using var refresh = await PostWithCookieAsync(client, "/auth/refresh", $"refresh_token={token}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, login.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, refresh.StatusCode);
        Assert.Empty(SetCookies(login));
        Assert.Empty(SetCookies(refresh));
    }
}
