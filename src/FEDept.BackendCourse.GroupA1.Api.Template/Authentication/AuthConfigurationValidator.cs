using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Authentication;

public sealed class AuthConfigurationValidator(
    IOptions<JwtOptions> jwt,
    IOptions<FrontendOptions> frontend,
    IHostEnvironment environment) : IValidateOptions<LoginOptions>
{
    public const int MinKeyBytes = 32;

    public ValidateOptionsResult Validate(string? name, LoginOptions options)
    {
        var errors = Errors(jwt.Value, options, frontend.Value, environment.IsDevelopment()).ToList();
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    public static IEnumerable<string> Errors(JwtOptions jwt, LoginOptions login, FrontendOptions frontend, bool isDevelopment)
    {
        (string Name, string Value)[] keys =
        [
            ("Jwt:AccessSecret", jwt.AccessSecret),
            ("Jwt:RefreshSecret", jwt.RefreshSecret),
            ("Login:ChallengeHmacKey", login.ChallengeHmacKey),
            ("Login:AuditHmacKey", login.AuditHmacKey)
        ];
        var shortKeys = keys.Where(key => Encoding.UTF8.GetByteCount(key.Value ?? string.Empty) < MinKeyBytes).ToList();
        foreach (var key in shortKeys)
        {
            yield return $"{key.Name} must be at least {MinKeyBytes} bytes.";
        }

        if (shortKeys.Count == 0 && keys.Select(key => key.Value).Distinct(StringComparer.Ordinal).Count() != keys.Length)
        {
            yield return "Jwt:AccessSecret, Jwt:RefreshSecret, Login:ChallengeHmacKey and Login:AuditHmacKey must all differ.";
        }

        if (login.LoginPermitPerMinute <= 0)
        {
            yield return "Login:LoginPermitPerMinute must be positive.";
        }

        if (login.RefreshPermitPerMinute <= 0)
        {
            yield return "Login:RefreshPermitPerMinute must be positive.";
        }

        if (string.IsNullOrWhiteSpace(jwt.Issuer))
        {
            yield return "Jwt:Issuer is required.";
        }

        if (string.IsNullOrWhiteSpace(jwt.Audience))
        {
            yield return "Jwt:Audience is required.";
        }

        if (!Enum.IsDefined(login.ConfirmationMethod))
        {
            yield return "Login:ConfirmationMethod must be Otp or MagicLink.";
        }

        if (login.ConfirmationMethod == ChallengeMethod.MagicLink && !IsMagicLinkBaseUrl(login.MagicLinkBaseUrl, isDevelopment))
        {
            yield return "Login:MagicLinkBaseUrl must be an absolute https URL without a fragment when the magic link method is enabled.";
        }

        if (frontend.Origin.Length > 0 && !IsOrigin(frontend.Origin))
        {
            yield return "Frontend:Origin must be an exact origin such as https://app.example.com.";
        }
    }

    private static bool IsMagicLinkBaseUrl(string value, bool isDevelopment) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || (isDevelopment && uri.Scheme == Uri.UriSchemeHttp))
        && uri.Fragment.Length == 0;

    private static bool IsOrigin(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
        && string.Equals(value, uri.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal);
}
