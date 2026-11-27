using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class LoginService(
    AppDbContext db,
    IOptionsSnapshot<LoginOptions> options,
    JwtTokenService tokens,
    FailedLoginLimiter failedLogins,
    ILoginEmailSender emailSender,
    AuthAudit audit)
{
    public const int MaxOtpAttempts = 5;
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan ResendPause = TimeSpan.FromSeconds(60);

    // prepared once; a missing account still costs one BCrypt check
    private static readonly string DummyHash = PasswordHasher.Hash(Guid.NewGuid().ToString());

    private SecretHasher Hasher => new(options.Value.ChallengeHmacKey);

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

        if (!options.Value.ConfirmationEnabled)
        {
            var pair = tokens.Issue(user.Id);
            audit.Login(user.Id, null, "success");
            return new LoginResult.SignedIn(pair);
        }

        return await StartChallengeAsync(user.Id, ct);
    }

    public async Task<TokenPair?> RefreshAsync(string? refreshToken, CancellationToken ct)
    {
        var validation = await tokens.ValidateAsync(refreshToken, TokenUse.Refresh);
        if (validation is TokenValidation.Fail fail)
        {
            audit.Refresh(null, "failure", fail.Category);
            return null;
        }

        var userId = ((TokenValidation.Ok)validation).UserId;
        if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == userId && user.Status == UserStatus.Active, ct))
        {
            audit.Refresh(userId, "failure", "user_inactive");
            return null;
        }

        // stateless: the used refresh token is not stored or denylisted
        var pair = tokens.Issue(userId);
        audit.Refresh(userId, "success", null);
        return pair;
    }

    public async Task<LoginConfirmResult> ConfirmAsync(Guid attemptId, ChallengeMethod method, string secret, CancellationToken ct)
    {
        var userId = await FindUserIdAsync(attemptId, ct);
        if (userId is null)
        {
            audit.Challenge(null, attemptId, method, "rejected");
            return LoginConfirmResult.Invalid.Instance;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var (user, challenge) = await LockAsync(userId.Value, attemptId, ct);
        if (challenge?.ConsumedReason == ConsumedReason.AttemptsExhausted)
        {
            audit.Challenge(userId, attemptId, challenge.Method, "exhausted");
            return LoginConfirmResult.Exhausted.Instance;
        }

        if (challenge is null || challenge.ConsumedAt is not null)
        {
            audit.Challenge(userId, attemptId, method, "rejected");
            return LoginConfirmResult.Invalid.Instance;
        }

        var now = DateTimeOffset.UtcNow;
        if (challenge.LastSentAt + ChallengeLifetime <= now)
        {
            audit.Challenge(userId, attemptId, method, "expired");
            return LoginConfirmResult.Invalid.Instance;
        }

        if (challenge.Method != method)
        {
            audit.Challenge(userId, attemptId, method, "rejected");
            return LoginConfirmResult.Invalid.Instance;
        }

        if (user is not { Status: UserStatus.Active })
        {
            await ConsumeAsync(challenge, ConsumedReason.UserInactive, now, transaction, ct);
            audit.Challenge(userId, attemptId, method, "user_inactive");
            return LoginConfirmResult.InvalidCredentials.Instance;
        }

        if (!Hasher.Matches(secret, challenge.SecretHash))
        {
            if (method == ChallengeMethod.Otp)
            {
                // the fifth entry is still checked; a fifth miss consumes the attempt
                challenge.Attempts++;
                if (challenge.Attempts >= MaxOtpAttempts)
                {
                    challenge.ConsumedAt = now;
                    challenge.ConsumedReason = ConsumedReason.AttemptsExhausted;
                }

                await db.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
            }

            audit.Challenge(userId, attemptId, method, challenge.ConsumedAt is null ? "wrong_entry" : "exhausted");
            return LoginConfirmResult.Invalid.Instance;
        }

        // sign before commit: a signing failure rolls back and the attempt stays confirmable
        var pair = tokens.Issue(user.Id);
        await ConsumeAsync(challenge, ConsumedReason.Confirmed, now, transaction, ct);
        audit.Challenge(userId, attemptId, method, "confirmed");
        return new LoginConfirmResult.SignedIn(pair);
    }

    public async Task<LoginResendResult> ResendAsync(Guid attemptId, CancellationToken ct)
    {
        var userId = await FindUserIdAsync(attemptId, ct);
        if (userId is null)
        {
            audit.Challenge(null, attemptId, null, "rejected");
            return LoginResendResult.Invalid.Instance;
        }

        LoginChallenge? challenge;
        string secret;
        string email;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            (var user, challenge) = await LockAsync(userId.Value, attemptId, ct);
            if (challenge?.ConsumedReason == ConsumedReason.AttemptsExhausted)
            {
                audit.Challenge(userId, attemptId, challenge.Method, "exhausted");
                return LoginResendResult.Exhausted.Instance;
            }

            if (challenge is null || challenge.ConsumedAt is not null)
            {
                audit.Challenge(userId, attemptId, challenge?.Method, "rejected");
                return LoginResendResult.Invalid.Instance;
            }

            var now = DateTimeOffset.UtcNow;
            if (user is not { Status: UserStatus.Active })
            {
                await ConsumeAsync(challenge, ConsumedReason.UserInactive, now, transaction, ct);
                audit.Challenge(userId, attemptId, challenge.Method, "user_inactive");
                return LoginResendResult.InvalidCredentials.Instance;
            }

            if (RetryAfter(challenge.LastSentAt, now) is { } wait)
            {
                audit.Challenge(userId, attemptId, challenge.Method, "cooldown");
                return new LoginResendResult.TooSoon(wait);
            }

            // an expired TTL does not block resend; the new send restarts it
            secret = GenerateSecret(challenge.Method);
            challenge.SecretHash = Hasher.Hash(secret);
            challenge.LastSentAt = now;
            challenge.Attempts = 0;
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            email = user.Email;
        }

        audit.Challenge(userId, attemptId, challenge.Method, "resent");
        // on SMTP failure the new hash stays; the old secret is not restored
        return await TrySendAsync(email, challenge, secret, ct)
            ? new LoginResendResult.Sent(challenge.Id, challenge.Method)
            : new LoginResendResult.NotSent(challenge.Id, challenge.Method);
    }

    private async Task<LoginResult> StartChallengeAsync(Guid userId, CancellationToken ct)
    {
        var lastSentAt = await db.LoginChallenges.AsNoTracking()
            .Where(challenge => challenge.UserId == userId && challenge.ConsumedAt == null)
            .Select(challenge => (DateTimeOffset?)challenge.LastSentAt)
            .SingleOrDefaultAsync(ct);
        if (RetryAfter(lastSentAt, DateTimeOffset.UtcNow) is { } wait)
        {
            audit.Login(userId, null, "cooldown");
            return new LoginResult.TooManyRequests(wait);
        }

        var method = options.Value.ConfirmationMethod;
        var secret = GenerateSecret(method);
        LoginChallenge challenge;
        string email;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            // lock order is user, then challenge, everywhere
            var user = await LockUserAsync(userId, ct);
            if (user is not { Status: UserStatus.Active })
            {
                audit.Login(userId, null, "invalid_credentials");
                return LoginResult.InvalidCredentials.Instance;
            }

            var previous = await db.LoginChallenges
                .FromSqlInterpolated($"SELECT * FROM login_challenges WHERE user_id = {userId} AND consumed_at IS NULL FOR UPDATE")
                .SingleOrDefaultAsync(ct);
            var now = DateTimeOffset.UtcNow;
            if (RetryAfter(previous?.LastSentAt, now) is { } lockedWait)
            {
                audit.Login(userId, null, "cooldown");
                return new LoginResult.TooManyRequests(lockedWait);
            }

            if (previous is not null)
            {
                previous.ConsumedAt = now;
                previous.ConsumedReason = ConsumedReason.Replaced;
                // separate save frees the partial unique index before the insert
                await db.SaveChangesAsync(ct);
            }

            challenge = new LoginChallenge
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Method = method,
                SecretHash = Hasher.Hash(secret),
                LastSentAt = now,
                Attempts = 0,
                CreatedAt = now
            };
            db.LoginChallenges.Add(challenge);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            email = user.Email;
        }

        audit.Challenge(userId, challenge.Id, method, "created");
        return await TrySendAsync(email, challenge, secret, ct)
            ? new LoginResult.ChallengeSent(challenge.Id, method)
            : new LoginResult.ChallengeNotSent(challenge.Id, method, (int)ResendPause.TotalSeconds);
    }

    private Task<Guid?> FindUserIdAsync(Guid attemptId, CancellationToken ct) =>
        db.LoginChallenges.AsNoTracking()
            .Where(challenge => challenge.Id == attemptId)
            .Select(challenge => (Guid?)challenge.UserId)
            .SingleOrDefaultAsync(ct);

    private Task<User?> LockUserAsync(Guid userId, CancellationToken ct) =>
        db.Users.FromSqlInterpolated($"SELECT * FROM \"Users\" WHERE \"Id\" = {userId} FOR UPDATE").SingleOrDefaultAsync(ct);

    private async Task<(User? User, LoginChallenge? Challenge)> LockAsync(Guid userId, Guid attemptId, CancellationToken ct)
    {
        var user = await LockUserAsync(userId, ct);
        var challenge = await db.LoginChallenges
            .FromSqlInterpolated($"SELECT * FROM login_challenges WHERE id = {attemptId} FOR UPDATE")
            .SingleOrDefaultAsync(ct);
        return (user, challenge);
    }

    private async Task ConsumeAsync(
        LoginChallenge challenge, ConsumedReason reason, DateTimeOffset now, IDbContextTransaction transaction, CancellationToken ct)
    {
        challenge.ConsumedAt = now;
        challenge.ConsumedReason = reason;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
    }

    private static int? RetryAfter(DateTimeOffset? lastSentAt, DateTimeOffset now)
    {
        var remaining = lastSentAt + ResendPause - now;
        return remaining > TimeSpan.Zero ? (int)Math.Ceiling(remaining.Value.TotalSeconds) : null;
    }

    private static string GenerateSecret(ChallengeMethod method) =>
        method == ChallengeMethod.MagicLink ? MagicLinkTokenGenerator.Generate() : OtpGenerator.Generate();

    private async Task<bool> TrySendAsync(string email, LoginChallenge challenge, string secret, CancellationToken ct)
    {
        try
        {
            if (challenge.Method == ChallengeMethod.MagicLink)
            {
                // the fragment never reaches the server or Referer; the page POSTs it to /auth/login/confirm
                await emailSender.SendLoginMagicLinkAsync(email, $"{options.Value.MagicLinkBaseUrl}#token={challenge.Id}.{secret}", ct);
            }
            else
            {
                await emailSender.SendLoginOtpAsync(email, secret, ct);
            }

            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            audit.Challenge(challenge.UserId, challenge.Id, challenge.Method, "send_failed");
            audit.DependencyUnavailable("smtp");
            return false;
        }
    }
}

public abstract record LoginResult
{
    public sealed record SignedIn(TokenPair Tokens) : LoginResult;

    public sealed record ChallengeSent(Guid AttemptId, ChallengeMethod Method) : LoginResult;

    public sealed record ChallengeNotSent(Guid AttemptId, ChallengeMethod Method, int RetryAfterSeconds) : LoginResult;

    public sealed record InvalidCredentials : LoginResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }

    public sealed record TooManyRequests(int RetryAfterSeconds) : LoginResult;
}

public abstract record LoginConfirmResult
{
    public sealed record SignedIn(TokenPair Tokens) : LoginConfirmResult;

    public sealed record Invalid : LoginConfirmResult
    {
        public static Invalid Instance { get; } = new();
    }

    public sealed record Exhausted : LoginConfirmResult
    {
        public static Exhausted Instance { get; } = new();
    }

    public sealed record InvalidCredentials : LoginConfirmResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }
}

public abstract record LoginResendResult
{
    public sealed record Sent(Guid AttemptId, ChallengeMethod Method) : LoginResendResult;

    public sealed record NotSent(Guid AttemptId, ChallengeMethod Method) : LoginResendResult;

    public sealed record TooSoon(int RetryAfterSeconds) : LoginResendResult;

    public sealed record Invalid : LoginResendResult
    {
        public static Invalid Instance { get; } = new();
    }

    public sealed record Exhausted : LoginResendResult
    {
        public static Exhausted Instance { get; } = new();
    }

    public sealed record InvalidCredentials : LoginResendResult
    {
        public static InvalidCredentials Instance { get; } = new();
    }
}
