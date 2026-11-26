using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class LoginService(
    AppDbContext db,
    IOptionsSnapshot<LoginOptions> options,
    JwtTokenService tokens,
    FailedLoginLimiter failedLogins,
    AuthAudit audit)
{
    // prepared once; a missing account still costs one BCrypt check
    private static readonly string DummyHash = PasswordHasher.Hash(Guid.NewGuid().ToString());

    public async Task<LoginResult> LoginAsync(string email, string password, string clientIp, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        var emailRef = audit.EmailRef(normalizedEmail);
        // reserves a failure slot before BCrypt, so concurrent guesses cannot exceed the limit
        if (failedLogins.TryBeginAttempt(emailRef, clientIp) is { } wait)
        {
            audit.Login(null, emailRef, "rate_limited_pair");
            return new LoginResult.TooManyRequests(wait);
        }

        User? user;
        bool valid;
        try
        {
            user = await db.Users.AsNoTracking().SingleOrDefaultAsync(item => item.Email == normalizedEmail, ct);
            valid = PasswordHasher.Verify(password, user?.PasswordHash ?? DummyHash) && user is { Status: UserStatus.Active };
        }
        catch
        {
            // an outage is not a failed check
            failedLogins.Release(emailRef, clientIp);
            throw;
        }

        if (!valid || user is null)
        {
            // the reserved slot stays as the recorded failure
            audit.Login(user?.Id, emailRef, "invalid_credentials");
            return LoginResult.InvalidCredentials.Instance;
        }

        failedLogins.Release(emailRef, clientIp);

        var pair = tokens.Issue(user.Id);
        audit.Login(user.Id, null, "success");
        return new LoginResult.SignedIn(pair);
    }
}

public abstract record LoginResult
{
    public sealed record SignedIn(TokenPair Tokens) : LoginResult;

    public sealed record InvalidCredentials : LoginResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }

    public sealed record TooManyRequests(int RetryAfterSeconds) : LoginResult;
}
