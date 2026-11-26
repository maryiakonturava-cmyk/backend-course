using System.Globalization;
using System.Threading.RateLimiting;
using FEDept.BackendCourse.GroupA1.Api.Template.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Contracts;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default")));
builder.Services.AddOptions<RegistrationOptions>()
    .Bind(builder.Configuration.GetSection("Registration"))
    .Validate(options => !options.ConfirmationEnabled || !string.IsNullOrWhiteSpace(options.HmacKey),
        "Registration:HmacKey must be configured when confirmation is enabled.")
    .Validate(options => Enum.IsDefined(options.ConfirmationMethod),
        "Registration:ConfirmationMethod must be Otp or MagicLink.")
    .Validate(options => !options.ConfirmationEnabled
            || options.ConfirmationMethod != ChallengeMethod.MagicLink
            || (Uri.TryCreate(options.MagicLinkBaseUrl, UriKind.Absolute, out var baseUrl)
                && (baseUrl.Scheme == Uri.UriSchemeHttp || baseUrl.Scheme == Uri.UriSchemeHttps)),
        "Registration:MagicLinkBaseUrl must be an absolute URL when the magic link method is enabled.")
    .ValidateOnStart();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("registration", context =>
    {
        var permitLimit = context.RequestServices.GetRequiredService<IOptions<RegistrationOptions>>().Value.RateLimitPermitPerWindow;
        return PerIpPerMinute(context, "registration", permitLimit);
    });
    options.AddPolicy("login", context => PerIpPerMinute(context, "login",
        context.RequestServices.GetRequiredService<IOptions<LoginOptions>>().Value.LoginPermitPerMinute));
    options.AddPolicy("refresh", context => PerIpPerMinute(context, "refresh",
        context.RequestServices.GetRequiredService<IOptions<LoginOptions>>().Value.RefreshPermitPerMinute));
    options.OnRejected = async (context, ct) =>
    {
        var http = context.HttpContext;
        var retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var wait)
            ? (int)Math.Ceiling(wait.TotalSeconds)
            : 60;
        http.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
        var audit = http.RequestServices.GetRequiredService<AuthAudit>();
        if (http.Request.Path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase))
        {
            audit.Login(null, null, "rate_limited_ip");
        }
        else if (http.Request.Path.Equals("/auth/refresh", StringComparison.OrdinalIgnoreCase))
        {
            audit.Refresh(null, "failure", "rate_limited_ip");
        }

        await http.Response.WriteAsJsonAsync(ErrorResponses.TooManyRequests(retryAfter), ct);
    };
});
builder.Services.AddOptions<SmtpOptions>()
    .Bind(builder.Configuration.GetSection("Smtp"));
builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection("Jwt"));
builder.Services.AddOptions<FrontendOptions>()
    .Bind(builder.Configuration.GetSection("Frontend"));
builder.Services.AddOptions<LoginOptions>()
    .Bind(builder.Configuration.GetSection("Login"))
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<LoginOptions>, AuthConfigurationValidator>();
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddSingleton<AuthAudit>();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<FailedLoginLimiter>();
builder.Services.AddSingleton<AuthCookies>();
builder.Services.AddScoped<LoginService>();
builder.Services.AddExceptionHandler<DependencyFailureHandler>();
builder.Services.AddProblemDetails();
builder.Services.AddScoped<RegistrationService>();
builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
builder.Services.AddControllers();

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment() && builder.Configuration.GetValue<bool>("Database:ApplyMigrations"))
{
    await using var scope = app.Services.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.MigrateAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// shortcut: KnownProxies/KnownNetworks not configured — set before production
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor
});
app.UseExceptionHandler(new ExceptionHandlerOptions { SuppressDiagnosticsCallback = _ => false });
app.UseHttpsRedirection();
app.UseRouting();
app.UseRateLimiter();

app.MapControllers();

app.MapGet("/health", () => Results.Ok())
    .WithName("GetHealth");

app.Run();

static RateLimitPartition<string> PerIpPerMinute(HttpContext context, string policy, int permitLimit) =>
    RateLimitPartition.GetFixedWindowLimiter(
        $"{policy}:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        });

public partial class Program;
