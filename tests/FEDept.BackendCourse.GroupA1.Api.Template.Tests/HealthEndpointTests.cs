using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class HealthEndpointTests(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client = factory
        .WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Database:ApplyMigrations"] = "false",
                    ["Jwt:AccessSecret"] = new string('a', 32),
                    ["Jwt:RefreshSecret"] = new string('b', 32),
                    ["Jwt:Issuer"] = "health-test-api",
                    ["Jwt:Audience"] = "health-test-web",
                    ["Login:ChallengeHmacKey"] = new string('c', 32),
                    ["Login:AuditHmacKey"] = new string('d', 32)
                }));
            builder.ConfigureLogging(logging => logging.ClearProviders());
        })
        .CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

    [Fact]
    public async Task GetHealth_ReturnsOk()
    {
        using var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
