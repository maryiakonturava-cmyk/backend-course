using System.Net.Http.Json;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
