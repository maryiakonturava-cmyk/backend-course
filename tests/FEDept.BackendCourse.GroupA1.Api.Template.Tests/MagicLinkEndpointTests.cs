using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
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
