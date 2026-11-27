using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using static FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth.AuthTestKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class BrowserProtectionTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    private const string Frontend = "https://app.example.test";

    private WebApplicationFactory<Program> WithFrontend(bool crossSite = false) =>
        factory.WithSettings(new Dictionary<string, string?>
        {
            ["Frontend:Origin"] = Frontend,
            ["Frontend:CrossSite"] = crossSite ? "true" : "false"
        });

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, string path, string? origin, bool csrfHeader = false, object? body = null, string? csrfHeaderValue = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = body is null ? null : JsonContent.Create(body) };
        if (origin is not null)
        {
            request.Headers.Add("Origin", origin);
        }

        if (csrfHeader || csrfHeaderValue is not null)
        {
            request.Headers.Add("X-CSRF-Protection", csrfHeaderValue ?? "1");
        }

        return client.SendAsync(request);
    }

    private static async Task AssertCsrfRejectedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("csrf_rejected", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://localhost")]
    public async Task Post_WithoutOriginOrFromOwnOrigin_Passes(string? origin)
    {
        using var client = CreateClient(factory);

        using var response = await PostAsync(client, "/auth/logout", origin);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("https://sub.app.example.test")]
    [InlineData("https://app.example.test/")]
    [InlineData("https://APP.EXAMPLE.TEST")]
    public async Task Post_FromNonExactOrigin_Returns403(string origin)
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, "/auth/logout", origin, csrfHeader: true);

        await AssertCsrfRejectedAsync(response);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("true")]
    public async Task Post_FromTrustedOriginWithInvalidHeader_Returns403(string csrfValue)
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, "/auth/logout", Frontend, csrfHeaderValue: csrfValue);

        await AssertCsrfRejectedAsync(response);
    }

    [Theory]
    [InlineData("/auth/logout")]
    [InlineData("/auth/refresh")]
    [InlineData("/auth/login")]
    [InlineData("/auth/register")]
    public async Task Post_FromForeignOrigin_Returns403(string path)
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, path, "https://evil.example", csrfHeader: true);

        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task Post_FromTrustedOriginWithoutHeader_Returns403()
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, "/auth/logout", Frontend);

        await AssertCsrfRejectedAsync(response);
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public async Task UnsafeMethod_FromForeignOrigin_Returns403(string method)
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);
        using var request = new HttpRequestMessage(new HttpMethod(method), "/auth/logout");
        request.Headers.Add("Origin", "https://evil.example");

        using var response = await client.SendAsync(request);

        await AssertCsrfRejectedAsync(response);
    }

    [Fact]
    public async Task Post_FromTrustedOriginWithHeader_PassesWithCorsHeaders()
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        using var response = await PostAsync(client, "/auth/logout", Frontend, csrfHeader: true);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(Frontend, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Credentials")));
    }

    [Fact]
    public async Task Preflight_TrustedOrigin_IsAllowed_ForeignOriginIsNot()
    {
        using var app = WithFrontend();
        using var client = CreateClient(app);

        HttpRequestMessage Preflight(string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Options, "/auth/login");
            request.Headers.Add("Origin", origin);
            request.Headers.Add("Access-Control-Request-Method", "POST");
            request.Headers.Add("Access-Control-Request-Headers", "content-type,x-csrf-protection");
            return request;
        }

        using var trusted = await client.SendAsync(Preflight(Frontend));
        using var foreign = await client.SendAsync(Preflight("https://evil.example"));

        Assert.Equal(HttpStatusCode.NoContent, trusted.StatusCode);
        Assert.Equal(Frontend, Assert.Single(trusted.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Equal("true", Assert.Single(trusted.Headers.GetValues("Access-Control-Allow-Credentials")));
        Assert.Contains("x-csrf-protection", string.Join(",", trusted.Headers.GetValues("Access-Control-Allow-Headers")), StringComparison.OrdinalIgnoreCase);
        Assert.False(foreign.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task AccessCookieHandler_AuthenticatesAuthorizationPolicyMetadata()
    {
        using var app = factory.WithSettings(new Dictionary<string, string?> { ["Login:ConfirmationEnabled"] = "false" });
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);
        using var login = await LoginAsync(client, email);
        var access = CookieValue(login, "access_token");
        using var scope = app.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Headers.Cookie = $"access_token={access}";
        var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(policy), "policy endpoint"));
        var handler = ActivatorUtilities.CreateInstance<AccessCookieAuthenticationHandler>(scope.ServiceProvider);
        await handler.InitializeAsync(new AuthenticationScheme(
            AccessCookieAuthenticationHandler.SchemeName, null, typeof(AccessCookieAuthenticationHandler)), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task CrossSiteFrontend_SwitchesCookiesToSameSiteNone()
    {
        using var app = WithFrontend(crossSite: true);
        using var client = CreateClient(app);
        var email = NewEmail();
        await CreateUserAsync(app.Services, email);

        using var response = await PostAsync(client, "/auth/login", Frontend, csrfHeader: true, new { email, password = Password });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        AssertSessionCookies(response, sameSite: "none");
    }

    [Fact]
    public async Task PlainHttpOutsideDevelopment_Returns400HttpsRequired()
    {
        using var app = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
        using var client = CreateClient(app, "http://localhost");

        using var response = await client.PostAsJsonAsync("/auth/login", new { email = "user@example.com", password = "x" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("https_required", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
    }
}
