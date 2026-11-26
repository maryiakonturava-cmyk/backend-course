using System.Security.Cryptography;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Testcontainers.PostgreSql;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class RegistrationTestFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:16-alpine").Build();
    private readonly string _accessSecret = NewKey();
    private readonly string _refreshSecret = NewKey();
    private readonly string _challengeKey = NewKey();
    private readonly string _auditKey = NewKey();

    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = _postgres.GetConnectionString(),
                ["Database:ApplyMigrations"] = "true",
                ["Jwt:AccessSecret"] = _accessSecret,
                ["Jwt:RefreshSecret"] = _refreshSecret,
                ["Jwt:Issuer"] = "groupa1-api-tests",
                ["Jwt:Audience"] = "groupa1-web-tests",
                ["Login:ChallengeHmacKey"] = _challengeKey,
                ["Login:AuditHmacKey"] = _auditKey,
                ["Login:MagicLinkBaseUrl"] = "https://app.example.test/login/confirm",
                ["Login:LoginPermitPerMinute"] = "10000",
                ["Login:RefreshPermitPerMinute"] = "10000"
            }));
        builder.ConfigureLogging(logging => logging.ClearProviders());
    }

    public new HttpClient CreateClient() => base.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost")
    });

    public Task InitializeAsync() => _postgres.StartAsync();

    async Task IAsyncLifetime.DisposeAsync()
    {
        await _postgres.DisposeAsync();
        await base.DisposeAsync();
    }
}
