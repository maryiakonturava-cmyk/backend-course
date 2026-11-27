using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class MagicLinkChallengeTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private const string BaseUrl = "https://app.example.test/login/confirm";
    private readonly CapturingLoginEmailSender _sender = new();
    private readonly WebApplicationFactory<Program> _app;
    private readonly HttpClient _client;

    public MagicLinkChallengeTests(RegistrationTestFactory factory)
    {
        _app = factory.WithChallenge("MagicLink", _sender);
        _client = CreateClient(_app);
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    private async Task<(string Email, Guid AttemptId, string Token)> StartAsync()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email);
        using var login = await LoginAsync(_client, email);
        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("magic_link", body.GetProperty("method").GetString());
        var link = _sender.LastFor(email);
        return (email, body.GetProperty("attemptId").GetGuid(), TokenFromLink(link));
    }

    private static string TokenFromLink(string link)
    {
        Assert.Contains("#token=", link, StringComparison.Ordinal);
        return link[(link.IndexOf("#token=", StringComparison.Ordinal) + 7)..];
    }

    private Task<HttpResponseMessage> ConfirmAsync(string token) =>
        _client.PostAsJsonAsync("/auth/login/confirm", new { token });

    [Fact]
    public async Task Login_SendsLinkWithTokenInFragmentOnly()
    {
        var (email, attemptId, token) = await StartAsync();

        var link = _sender.LastFor(email);

        Assert.StartsWith($"{BaseUrl}#token=", link, StringComparison.Ordinal);
        Assert.DoesNotContain("?", link, StringComparison.Ordinal);
        Assert.Matches($"^{attemptId}\\.[A-Za-z0-9_-]{{43}}$", token);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(ChallengeHash(_app.Services, token[37..]), challenge.SecretHash);
    }

    [Fact]
    public async Task Confirm_ValidToken_SetsCookies()
    {
        var (_, attemptId, token) = await StartAsync();

        using var response = await ConfirmAsync(token);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        AssertSessionCookies(response);
        Assert.Equal(ConsumedReason.Confirmed, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
        using var replay = await ConfirmAsync(token);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Fact]
    public async Task Confirm_WrongSecret_Returns400WithoutCounting()
    {
        var (_, attemptId, token) = await StartAsync();
        var wrong = $"{attemptId}.{new string('A', 43)}";

        for (var i = 0; i < 6; i++)
        {
            using var response = await ConfirmAsync(wrong);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        Assert.Equal(0, (await GetChallengeAsync(_app.Services, attemptId)).Attempts);
        using var valid = await ConfirmAsync(token);
        Assert.Equal(HttpStatusCode.NoContent, valid.StatusCode);
    }

    [Fact]
    public async Task Confirm_OtpShapeForLinkAttempt_Returns400()
    {
        var (_, attemptId, token) = await StartAsync();

        using var response = await _client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code = "123456" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(0, challenge.Attempts);
        Assert.Null(challenge.ConsumedAt);
        using var valid = await ConfirmAsync(token);
        Assert.Equal(HttpStatusCode.NoContent, valid.StatusCode);
    }

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11.tooShort")]
    [InlineData("5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Confirm_MalformedToken_Returns400(string token)
    {
        using var response = await ConfirmAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Confirm_Expired_Returns400()
    {
        var (_, attemptId, token) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromMinutes(10));

        using var response = await ConfirmAsync(token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Null(challenge.ConsumedAt);
        Assert.Equal(0, challenge.Attempts);
    }

    [Fact]
    public async Task Resend_ReplacesLink_OldLinkStopsWorking()
    {
        var (email, attemptId, oldToken) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await _client.PostAsJsonAsync("/auth/login/resend", new { attemptId });

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal("magic_link", (await resend.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("method").GetString());
        var link = _sender.LastFor(email);
        var newToken = TokenFromLink(link);
        using var old = await ConfirmAsync(oldToken);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var fresh = await ConfirmAsync(newToken);
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }
}
