using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class OtpChallengeTests : IClassFixture<RegistrationTestFactory>, IDisposable
{
    private readonly RegistrationTestFactory _factory;
    private readonly CapturingLoginEmailSender _sender = new();
    private readonly WebApplicationFactory<Program> _app;
    private readonly HttpClient _client;

    public OtpChallengeTests(RegistrationTestFactory factory)
    {
        _factory = factory;
        _app = factory.WithChallenge("Otp", _sender);
        _client = CreateClient(_app);
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    private async Task<(string Email, Guid UserId, Guid AttemptId)> StartAsync()
    {
        var email = NewEmail();
        var userId = await CreateUserAsync(_app.Services, email);
        using var login = await LoginAsync(_client, email);
        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        return (email, userId, body.GetProperty("attemptId").GetGuid());
    }

    private Task<HttpResponseMessage> ConfirmAsync(Guid attemptId, string code) =>
        _client.PostAsJsonAsync("/auth/login/confirm", new { attemptId, code });

    private Task<HttpResponseMessage> ResendAsync(Guid attemptId) =>
        _client.PostAsJsonAsync("/auth/login/resend", new { attemptId });

    private static string WrongCode(string code) => code == "000000" ? "111111" : "000000";

    [Fact]
    public async Task Login_ReturnsAcceptedWithoutSecretOrCookies()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email);

        using var login = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.Accepted, login.StatusCode);
        Assert.Empty(SetCookies(login));
        var json = await login.Content.ReadAsStringAsync();
        var body = JsonDocument.Parse(json).RootElement;
        Assert.True(body.GetProperty("confirmationRequired").GetBoolean());
        Assert.Equal("otp", body.GetProperty("method").GetString());
        Assert.Equal(600, body.GetProperty("expiresInSeconds").GetInt32());
        Assert.Equal(60, body.GetProperty("resendAfterSeconds").GetInt32());
        var code = _sender.LastFor(email);
        Assert.Matches("^[0-9]{6}$", code);
        Assert.DoesNotContain(code, json, StringComparison.Ordinal);
        var challenge = await GetChallengeAsync(_app.Services, body.GetProperty("attemptId").GetGuid());
        Assert.Equal(ChallengeHash(_app.Services, code), challenge.SecretHash);
        Assert.Null(challenge.ConsumedAt);
    }

    [Fact]
    public async Task Login_InactiveUser_Returns401WithoutEmail()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email, UserStatus.Blocked);

        using var login = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Equal(0, _sender.CountFor(email));
    }

    [Fact]
    public async Task Confirm_CorrectCode_SetsCookiesAndConsumesAttempt()
    {
        var (email, _, attemptId) = await StartAsync();

        using var response = await ConfirmAsync(attemptId, _sender.LastFor(email));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync());
        AssertSessionCookies(response);
        Assert.Equal(ConsumedReason.Confirmed, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
        using var again = await ConfirmAsync(attemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
    }

    [Fact]
    public async Task Confirm_FifthWrongCodeConsumes_NextEntryReturns429()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);
        for (var i = 1; i <= 5; i++)
        {
            using var wrong = await ConfirmAsync(attemptId, WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(5, challenge.Attempts);
        Assert.Equal(ConsumedReason.AttemptsExhausted, challenge.ConsumedReason);
        using var next = await ConfirmAsync(attemptId, code);
        Assert.Equal(HttpStatusCode.TooManyRequests, next.StatusCode);
    }

    [Fact]
    public async Task Confirm_CorrectFifthEntry_Succeeds()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);
        for (var i = 1; i <= 4; i++)
        {
            using var wrong = await ConfirmAsync(attemptId, WrongCode(code));
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        using var fifth = await ConfirmAsync(attemptId, code);

        Assert.Equal(HttpStatusCode.NoContent, fifth.StatusCode);
    }

    [Fact]
    public async Task Confirm_Expired_Returns400WithoutCountingTheEntry()
    {
        var (email, _, attemptId) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromMinutes(10));

        using var response = await ConfirmAsync(attemptId, _sender.LastFor(email));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, (await GetChallengeAsync(_app.Services, attemptId)).Attempts);
    }

    [Fact]
    public async Task Confirm_UnknownAttempt_Returns400()
    {
        using var response = await ConfirmAsync(Guid.NewGuid(), "123456");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"12345\"}")]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"abcdef\"}")]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"١٢٣٤٥٦\"}")]
    [InlineData("{\"attemptId\":\"5b0f7b0e-1f55-4a0e-9a59-3f8d8a1d2c11\",\"code\":\"123456\\n\"}")]
    [InlineData("{\"code\":\"123456\"}")]
    [InlineData("{\"token\":\"short\"}")]
    [InlineData("{}")]
    public async Task Confirm_InvalidFormat_Returns400(string json)
    {
        using var response = await _client.PostAsync("/auth/login/confirm", new StringContent(json, System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Confirm_UserBlockedMidChallenge_Returns401AndConsumesAsUserInactive()
    {
        var (email, userId, attemptId) = await StartAsync();
        await SetStatusAsync(_app.Services, userId, UserStatus.Blocked);

        using var response = await ConfirmAsync(attemptId, _sender.LastFor(email));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_credentials", body.GetProperty("code").GetString());
        Assert.Equal(ConsumedReason.UserInactive, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
        using var resend = await ResendAsync(attemptId);
        Assert.Equal(HttpStatusCode.BadRequest, resend.StatusCode);
    }

    [Fact]
    public async Task Login_WithinPause_Returns429WithoutNewEmail()
    {
        var (email, _, _) = await StartAsync();

        using var second = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        var body = await second.Content.ReadFromJsonAsync<JsonElement>();
        Assert.InRange(body.GetProperty("retryAfterSeconds").GetInt32(), 1, 60);
        Assert.Equal(1, _sender.CountFor(email));
    }

    [Fact]
    public async Task Login_AfterPause_ReplacesPreviousAttempt()
    {
        var (email, _, oldAttemptId) = await StartAsync();
        var oldCode = _sender.LastFor(email);
        await AgeChallengeAsync(_app.Services, oldAttemptId, TimeSpan.FromSeconds(61));

        using var second = await LoginAsync(_client, email);

        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        var newAttemptId = (await second.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("attemptId").GetGuid();
        Assert.NotEqual(oldAttemptId, newAttemptId);
        Assert.Equal(ConsumedReason.Replaced, (await GetChallengeAsync(_app.Services, oldAttemptId)).ConsumedReason);
        using var old = await ConfirmAsync(oldAttemptId, oldCode);
        Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        using var fresh = await ConfirmAsync(newAttemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }

    [Fact]
    public async Task Resend_WithinPause_Returns429()
    {
        var (_, _, attemptId) = await StartAsync();

        using var response = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.True(response.Headers.RetryAfter is not null);
    }

    [Fact]
    public async Task Resend_AfterPause_ReplacesSecretAndResetsAttempts()
    {
        var (email, _, attemptId) = await StartAsync();
        var oldCode = _sender.LastFor(email);
        using (var wrong = await ConfirmAsync(attemptId, WrongCode(oldCode)))
        {
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        var body = await resend.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("otp", body.GetProperty("method").GetString());
        Assert.Equal(attemptId, body.GetProperty("attemptId").GetGuid());
        Assert.Equal(600, body.GetProperty("expiresInSeconds").GetInt32());
        Assert.Equal(60, body.GetProperty("resendAfterSeconds").GetInt32());
        var newCode = _sender.LastFor(email);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.Equal(0, challenge.Attempts);
        Assert.Equal(ChallengeHash(_app.Services, newCode), challenge.SecretHash);
        if (newCode != oldCode)
        {
            using var old = await ConfirmAsync(attemptId, oldCode);
            Assert.Equal(HttpStatusCode.BadRequest, old.StatusCode);
        }

        using var fresh = await ConfirmAsync(attemptId, newCode);
        Assert.Equal(HttpStatusCode.NoContent, fresh.StatusCode);
    }

    [Fact]
    public async Task Resend_AfterExpiry_IsAllowed()
    {
        var (email, _, attemptId) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromMinutes(11));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        using var confirm = await ConfirmAsync(attemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_ExhaustedAttempt_Returns429()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);
        for (var i = 0; i < 5; i++)
        {
            using var wrong = await ConfirmAsync(attemptId, WrongCode(code));
        }

        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.TooManyRequests, resend.StatusCode);
    }

    [Fact]
    public async Task Resend_UnknownOrConfirmedAttempt_Returns400()
    {
        var (email, _, attemptId) = await StartAsync();
        using (var confirm = await ConfirmAsync(attemptId, _sender.LastFor(email)))
        {
            Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
        }

        using var confirmed = await ResendAsync(attemptId);
        using var unknown = await ResendAsync(Guid.NewGuid());

        Assert.Equal(HttpStatusCode.BadRequest, confirmed.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"attemptId\":null}")]
    public async Task Resend_InvalidFormat_Returns400(string json)
    {
        using var response = await _client.PostAsync("/auth/login/resend", new StringContent(json, System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Resend_UserBlockedMidChallenge_Returns401WithoutEmail()
    {
        var (email, userId, attemptId) = await StartAsync();
        await SetStatusAsync(_app.Services, userId, UserStatus.Blocked);
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));

        using var resend = await ResendAsync(attemptId);

        Assert.Equal(HttpStatusCode.Unauthorized, resend.StatusCode);
        var body = await resend.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_credentials", body.GetProperty("code").GetString());
        Assert.Equal(1, _sender.CountFor(email));
        Assert.Equal(ConsumedReason.UserInactive, (await GetChallengeAsync(_app.Services, attemptId)).ConsumedReason);
    }

    // the row lock must serialize the counter: 5 wrong entries count, the rest see the exhausted attempt
    [Fact]
    public async Task ConcurrentWrongConfirms_CounterExact()
    {
        var (email, _, attemptId) = await StartAsync();
        var wrong = WrongCode(_sender.LastFor(email));

        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => ConfirmAsync(attemptId, wrong)));

        var statuses = responses.Select(response => response.StatusCode).ToArray();
        foreach (var response in responses)
        {
            response.Dispose();
        }

        Assert.Equal(5, statuses.Count(status => status == HttpStatusCode.BadRequest));
        Assert.Equal(7, statuses.Count(status => status == HttpStatusCode.TooManyRequests));
        Assert.Equal(5, (await GetChallengeAsync(_app.Services, attemptId)).Attempts);
    }

    [Fact]
    public async Task ConcurrentCorrectConfirms_SingleUse()
    {
        var (email, _, attemptId) = await StartAsync();
        var code = _sender.LastFor(email);

        var responses = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => ConfirmAsync(attemptId, code)));

        var statuses = responses.Select(response => response.StatusCode).ToArray();
        foreach (var response in responses)
        {
            response.Dispose();
        }

        Assert.Equal(1, statuses.Count(status => status == HttpStatusCode.NoContent));
        Assert.Equal(9, statuses.Count(status => status == HttpStatusCode.BadRequest));
    }

    [Fact]
    public async Task Resend_KeepsTheStoredMethodAfterConfigurationChanges()
    {
        var (email, _, attemptId) = await StartAsync();
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));
        var linkSender = new CapturingLoginEmailSender();
        using var magicLinkApp = _factory.WithChallenge("MagicLink", linkSender);
        using var magicLinkClient = CreateClient(magicLinkApp);

        using var resend = await magicLinkClient.PostAsJsonAsync("/auth/login/resend", new { attemptId });

        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        Assert.Equal("otp", (await resend.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("method").GetString());
        Assert.Matches("^[0-9]{6}$", linkSender.LastFor(email));
    }

    [Fact]
    public async Task Login_SmtpFailure_Returns503WithAttemptAndKeepsIt()
    {
        var email = NewEmail();
        await CreateUserAsync(_app.Services, email);
        _sender.Fail = true;

        using var login = await LoginAsync(_client, email);

        _sender.Fail = false;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("confirmationRequired").GetBoolean());
        Assert.Equal("otp", body.GetProperty("method").GetString());
        Assert.Equal(60, body.GetProperty("retryAfterSeconds").GetInt32());
        var attemptId = body.GetProperty("attemptId").GetGuid();
        Assert.Null((await GetChallengeAsync(_app.Services, attemptId)).ConsumedAt);
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));
        using var resend = await ResendAsync(attemptId);
        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);
        using var confirm = await ConfirmAsync(attemptId, _sender.LastFor(email));
        Assert.Equal(HttpStatusCode.NoContent, confirm.StatusCode);
    }

    [Fact]
    public async Task Resend_SmtpFailure_Returns503AndKeepsTheNewHash()
    {
        var (_, _, attemptId) = await StartAsync();
        var oldHash = (await GetChallengeAsync(_app.Services, attemptId)).SecretHash;
        await AgeChallengeAsync(_app.Services, attemptId, TimeSpan.FromSeconds(61));
        _sender.Fail = true;

        using var resend = await ResendAsync(attemptId);

        _sender.Fail = false;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resend.StatusCode);
        var challenge = await GetChallengeAsync(_app.Services, attemptId);
        Assert.NotEqual(oldHash, challenge.SecretHash);
        Assert.True(DateTimeOffset.UtcNow - challenge.LastSentAt < TimeSpan.FromSeconds(60));
    }
}
