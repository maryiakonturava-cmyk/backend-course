using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class RateLimitTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    [Fact]
    public async Task Register_ExceedingConfiguredConfirmLimit_RemainsAvailable()
    {
        using var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:RateLimitPermitPerWindow"] = "2",
                    ["Registration:ConfirmationEnabled"] = "false"
                })));
        Assert.Equal(2, app.Services.GetRequiredService<IOptions<RegistrationOptions>>().Value.RateLimitPermitPerWindow);
        var registerEndpoint = app.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
            .SelectMany(source => source.Endpoints)
            .Single(endpoint => endpoint.DisplayName?.Contains("Register (", StringComparison.Ordinal) == true);
        Assert.Null(registerEndpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>());
        using var client = app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        using var first = await client.PostAsJsonAsync("/auth/register", new RegisterRequest("first@example.com", "abc12345"));
        using var second = await client.PostAsJsonAsync("/auth/register", new RegisterRequest("second@example.com", "abc12345"));
        using var third = await client.PostAsJsonAsync("/auth/register", new RegisterRequest("third@example.com", "abc12345"));
        using var health = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        Assert.Equal(HttpStatusCode.Created, third.StatusCode);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    [Fact]
    public async Task Resend_ExceedingConfiguredConfirmLimit_RemainsAvailable()
    {
        using var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:RateLimitPermitPerWindow"] = "2",
                    ["Registration:ConfirmationEnabled"] = "true",
                    ["Registration:HmacKey"] = "test-key"
                })));
        using var client = app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        for (var i = 0; i < 3; i++)
        {
            using var response = await client.PostAsJsonAsync("/auth/register/resend", new { email = $"missing-{i}@example.com" });
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    [Fact]
    public async Task Confirm_ExceedingConfiguredLimit_ReturnsTooManyRequests()
    {
        using var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:RateLimitPermitPerWindow"] = "2",
                    ["Registration:ConfirmationEnabled"] = "true",
                    ["Registration:HmacKey"] = "test-key"
                })));
        using var client = app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        using var first = await client.PostAsJsonAsync("/auth/register/confirm", new { attemptId = Guid.NewGuid(), code = "123456" });
        using var second = await client.PostAsJsonAsync("/auth/register/confirm", new { attemptId = Guid.NewGuid(), code = "123456" });
        using var third = await client.PostAsJsonAsync("/auth/register/confirm", new { attemptId = Guid.NewGuid(), code = "123456" });

        Assert.Equal(HttpStatusCode.BadRequest, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    [Fact]
    public void ConfirmationEnabled_WithoutHmacKey_FailsOnStartup()
    {
        using var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:ConfirmationEnabled"] = "true",
                    ["Registration:HmacKey"] = ""
                })));

        var exception = Record.Exception(() => app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        }));

        Assert.NotNull(exception);
        Assert.Contains("HmacKey", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegistrationEndpoints_AppearInOpenApiWithTheirResponseStatuses()
    {
        using var app = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Registration:RateLimitPermitPerWindow"] = "2"
                })));
        using var client = app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var response = await client.GetAsync("/openapi/v1.json");
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var paths = document.RootElement.GetProperty("paths");

        AssertResponseCodes(paths, "/auth/register", "201", "202", "400", "409", "429", "503");
        AssertResponseCodes(paths, "/auth/register/resend", "202", "400", "404", "429", "503");
        AssertResponseCodes(paths, "/auth/register/confirm", "200", "400", "429");
    }

    private static void AssertResponseCodes(JsonElement paths, string path, params string[] expected)
    {
        var responses = paths.GetProperty(path).GetProperty("post").GetProperty("responses");
        var actual = responses.EnumerateObject().Select(response => response.Name).ToHashSet(StringComparer.Ordinal);
        Assert.Subset(expected.ToHashSet(StringComparer.Ordinal), actual);
    }
}
