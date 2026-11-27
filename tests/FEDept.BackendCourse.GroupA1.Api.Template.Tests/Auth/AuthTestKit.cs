using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

internal static class AuthTestKit
{
    // trailing space: login must not trim or normalize the password
    public const string Password = "Login password 42 ";
    private static readonly Lazy<string> PasswordHash = new(() => PasswordHasher.Hash(Password));

    public static string NewEmail() => $"login-{Guid.NewGuid():N}@example.com";

    public static WebApplicationFactory<Program> WithSettings(
        this RegistrationTestFactory factory,
        IDictionary<string, string?> settings,
        Action<IServiceCollection>? services = null) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(settings));
            if (services is not null)
            {
                builder.ConfigureTestServices(services);
            }
        });

    public static WebApplicationFactory<Program> WithChallenge(
        this RegistrationTestFactory factory, string method, CapturingLoginEmailSender sender) =>
        factory.WithSettings(
            new Dictionary<string, string?>
            {
                ["Login:ConfirmationEnabled"] = "true",
                ["Login:ConfirmationMethod"] = method
            },
            services =>
            {
                services.RemoveAll<ILoginEmailSender>();
                services.AddSingleton<ILoginEmailSender>(sender);
            });

    public static async Task<LoginChallenge> GetChallengeAsync(IServiceProvider services, Guid attemptId)
    {
        using var scope = services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AppDbContext>().LoginChallenges
            .AsNoTracking()
            .SingleAsync(challenge => challenge.Id == attemptId);
    }

    // moves the send time back instead of waiting for the 60 s pause or the 10 min TTL
    public static async Task AgeChallengeAsync(IServiceProvider services, Guid attemptId, TimeSpan by)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var challenge = await db.LoginChallenges.SingleAsync(item => item.Id == attemptId);
        challenge.LastSentAt -= by;
        await db.SaveChangesAsync();
    }

    public static string ChallengeHash(IServiceProvider services, string secret) =>
        new SecretHasher(services.GetRequiredService<IOptions<LoginOptions>>().Value.ChallengeHmacKey).Hash(secret);

    public static HttpClient CreateClient(WebApplicationFactory<Program> app, string baseAddress = "https://localhost") =>
        app.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            HandleCookies = false,
            AllowAutoRedirect = false
        });

    public static async Task<Guid> CreateUserAsync(IServiceProvider services, string email, UserStatus status = UserStatus.Active)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            PasswordHash = PasswordHash.Value,
            Status = status,
            CreatedAt = now,
            UpdatedAt = now
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user.Id;
    }

    public static async Task SetStatusAsync(IServiceProvider services, Guid userId, UserStatus status)
    {
        using var scope = services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AppDbContext>().Users
            .Where(user => user.Id == userId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(user => user.Status, status));
    }

    public static Task<HttpResponseMessage> LoginAsync(HttpClient client, string email, string password = Password) =>
        client.PostAsJsonAsync("/auth/login", new { email, password });

    public static Task<HttpResponseMessage> PostWithCookieAsync(HttpClient client, string path, string? cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        if (cookie is not null)
        {
            request.Headers.Add("Cookie", cookie);
        }

        return client.SendAsync(request);
    }

    public static string[] SetCookies(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToArray() : [];

    public static string SetCookie(HttpResponseMessage response, string name)
    {
        var matches = SetCookies(response).Where(header => header.StartsWith(name + "=", StringComparison.Ordinal)).ToArray();
        Assert.Single(matches);
        return matches[0];
    }

    public static string CookieValue(HttpResponseMessage response, string name)
    {
        var header = SetCookie(response, name);
        return header[(name.Length + 1)..header.IndexOf(';')];
    }

    public static void AssertSessionCookies(HttpResponseMessage response, string sameSite = "strict")
    {
        var access = SetCookie(response, "access_token").ToLowerInvariant();
        var refresh = SetCookie(response, "refresh_token").ToLowerInvariant();
        Assert.Contains("path=/;", access, StringComparison.Ordinal);
        Assert.Contains("max-age=900", access, StringComparison.Ordinal);
        Assert.Contains("path=/auth/refresh", refresh, StringComparison.Ordinal);
        Assert.Contains("max-age=2592000", refresh, StringComparison.Ordinal);
        foreach (var header in new[] { access, refresh })
        {
            Assert.Contains("secure", header, StringComparison.Ordinal);
            Assert.Contains("httponly", header, StringComparison.Ordinal);
            Assert.Contains($"samesite={sameSite}", header, StringComparison.Ordinal);
            Assert.DoesNotContain("domain=", header, StringComparison.Ordinal);
        }
    }
}

// Capture every category and scope so secret checks also cover framework and database logs.
public sealed class CapturingLoggerProvider : ILoggerProvider, ISupportExternalScope
{
    private IExternalScopeProvider _scopes = new LoggerExternalScopeProvider();

    public ConcurrentQueue<string> Messages { get; } = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(CapturingLoggerProvider provider, string categoryName) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => provider._scopes.Push(state);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var line = new StringBuilder(categoryName).Append(" | ").Append(formatter(state, exception));
            provider._scopes.ForEachScope((scope, builder) => builder.Append(" | ").Append(scope), line);
            provider.Messages.Enqueue(line.ToString());
        }
    }
}

public sealed class CapturingLoginEmailSender : ILoginEmailSender
{
    public ConcurrentQueue<(string Email, string Secret)> Sent { get; } = new();

    public bool Fail { get; set; }

    public Task SendLoginOtpAsync(string email, string code, CancellationToken ct) => Capture(email, code);

    public Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct) => Capture(email, link);

    public string LastFor(string email) => Sent.Last(item => item.Email == email).Secret;

    public int CountFor(string email) => Sent.Count(item => item.Email == email);

    private Task Capture(string email, string secret)
    {
        if (Fail)
        {
            throw new InvalidOperationException("SMTP rejected the message.");
        }

        Sent.Enqueue((email, secret));
        return Task.CompletedTask;
    }
}
