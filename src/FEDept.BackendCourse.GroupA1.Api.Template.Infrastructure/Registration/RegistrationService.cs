using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class RegistrationService(
    AppDbContext db,
    IOptions<RegistrationOptions> options,
    IEmailSender emailSender,
    ILogger<RegistrationService> logger)
{
    public async Task<RegisterResult> RegisterAsync(string email, string password, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        try
        {
            var existingUser = await db.Users.SingleOrDefaultAsync(user => user.Email == normalizedEmail, ct);
            if (existingUser is not null)
            {
                RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "failure");
                return RegisterResult.Conflict.Instance;
            }

            var now = DateTimeOffset.UtcNow;
            var confirmationEnabled = options.Value.ConfirmationEnabled;
            var user = new User
            {
                Id = Guid.NewGuid(),
                Email = normalizedEmail,
                PasswordHash = PasswordHasher.Hash(password),
                Status = confirmationEnabled ? UserStatus.Pending : UserStatus.Active,
                CreatedAt = now,
                UpdatedAt = now
            };
            var method = options.Value.ConfirmationMethod;
            var secret = confirmationEnabled ? GenerateSecret(method) : null;
            var challenge = confirmationEnabled
                ? new RegistrationChallenge
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Method = method,
                    SecretHash = new SecretHasher(options.Value.HmacKey).Hash(secret!),
                    ExpiresAt = now.AddSeconds(600),
                    Attempts = 0,
                    LastSentAt = now,
                    ConsumedAt = null
                }
                : null;

            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            try
            {
                db.Users.Add(user);
                if (challenge is not null)
                {
                    db.RegistrationChallenges.Add(challenge);
                }

                await db.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);

                if (secret is not null)
                {
                    await SendSecretAsync(normalizedEmail, method, secret, ct);
                    RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "success");
                    return new RegisterResult.ConfirmationRequired(challenge!.Id, method);
                }

                RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "success");
                return new RegisterResult.Active(user.Id, user.Email);
            }
            catch (DbUpdateException exception) when (
                exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                await transaction.RollbackAsync(ct);
                await transaction.DisposeAsync();
                db.ChangeTracker.Clear();
                var conflictingUser = await db.Users.SingleOrDefaultAsync(item => item.Email == normalizedEmail, ct);
                if (conflictingUser is null)
                {
                    throw;
                }

                RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "failure");
                return RegisterResult.Conflict.Instance;
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            RegistrationAudit.RegistrationAttempt(logger, normalizedEmail, "failure");
            throw;
        }
    }

    public async Task<ResendResult> ResendAsync(string email, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        var user = await db.Users.SingleOrDefaultAsync(item => item.Email == normalizedEmail, ct);
        if (user is null || user.Status != UserStatus.Pending)
        {
            return ResendResult.NotFound.Instance;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var challenge = await db.RegistrationChallenges
            .FromSqlInterpolated($"SELECT * FROM \"registration_challenges\" WHERE \"user_id\" = {user.Id} FOR UPDATE")
            .SingleAsync(ct);
        if (!await db.Users.AnyAsync(item => item.Id == user.Id && item.Status == UserStatus.Pending, ct))
        {
            return ResendResult.NotFound.Instance;
        }

        var now = DateTimeOffset.UtcNow;
        if (now - challenge.LastSentAt < TimeSpan.FromSeconds(60))
        {
            return ResendResult.TooSoon.Instance;
        }

        var code = OtpGenerator.Generate();
        challenge.SecretHash = new SecretHasher(options.Value.HmacKey).Hash(code);
        challenge.ExpiresAt = now.AddSeconds(600);
        challenge.Attempts = 0;
        challenge.LastSentAt = now;
        challenge.ConsumedAt = null;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);

        await SendSecretAsync(user.Email, ChallengeMethod.Otp, code, ct);
        return new ResendResult.Sent(challenge.Id);
    }

    public async Task<ConfirmResult> ConfirmAsync(Guid attemptId, string code, CancellationToken ct)
    {
        string? normalizedEmail = null;
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            // row lock: FOR UPDATE serializes concurrent confirms so the 5-attempt cap holds
            var challenge = await db.RegistrationChallenges
                .FromSqlInterpolated($"SELECT * FROM \"registration_challenges\" WHERE \"id\" = {attemptId} FOR UPDATE")
                .SingleOrDefaultAsync(ct);
            if (challenge is null)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }

            var user = await db.Users.SingleOrDefaultAsync(item => item.Id == challenge.UserId, ct);
            normalizedEmail = user?.Email;
            if (user is null)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }

            if (challenge.Attempts >= 5)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Exhausted.Instance;
            }

            if (challenge.ConsumedAt is not null)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }

            var now = DateTimeOffset.UtcNow;
            if (challenge.ExpiresAt <= now)
            {
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }

            if (!new SecretHasher(options.Value.HmacKey).Matches(code, challenge.SecretHash))
            {
                challenge.Attempts++;
                if (challenge.Attempts >= 5)
                {
                    challenge.ConsumedAt = now;
                    await db.SaveChangesAsync(ct);
                    await transaction.CommitAsync(ct);
                    RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                    return ConfirmResult.Invalid.Instance;
                }

                await db.SaveChangesAsync(ct);
                await transaction.CommitAsync(ct);
                RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
                return ConfirmResult.Invalid.Instance;
            }

            user.Status = UserStatus.Active;
            user.UpdatedAt = now;
            challenge.ConsumedAt = now;
            // shortcut: assign user role here once RBAC module exists
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "success");
            return new ConfirmResult.Success(user);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            RegistrationAudit.RegistrationConfirm(logger, normalizedEmail, "failure");
            throw;
        }
    }

    private static string GenerateSecret(ChallengeMethod method) =>
        method == ChallengeMethod.MagicLink ? MagicLinkTokenGenerator.Generate() : OtpGenerator.Generate();

    private string BuildMagicLink(string token)
    {
        var baseUrl = options.Value.MagicLinkBaseUrl;
        // base64url token needs no escaping
        return $"{baseUrl}{(baseUrl.Contains('?') ? '&' : '?')}token={token}";
    }

    private async Task SendSecretAsync(string email, ChallengeMethod method, string secret, CancellationToken ct)
    {
        try
        {
            if (method == ChallengeMethod.MagicLink)
            {
                await emailSender.SendMagicLinkAsync(email, BuildMagicLink(secret), ct);
            }
            else
            {
                await emailSender.SendOtpAsync(email, secret, ct);
            }

            RegistrationAudit.RegistrationCodeSent(logger, email, method.ToContractName(), "success");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            RegistrationAudit.RegistrationCodeSent(logger, email, method.ToContractName(), "failure");
            throw new EmailDeliveryException(exception);
        }
    }
}

public abstract record RegisterResult
{
    public sealed record Active(Guid Id, string Email) : RegisterResult;

    public sealed record ConfirmationRequired(Guid AttemptId, ChallengeMethod Method) : RegisterResult;

    public sealed record Conflict : RegisterResult
    {
        public static Conflict Instance { get; } = new();
    }
}

public abstract record ResendResult
{
    public sealed record Sent(Guid AttemptId) : ResendResult;

    public sealed record TooSoon : ResendResult
    {
        public static TooSoon Instance { get; } = new();
    }

    public sealed record NotFound : ResendResult
    {
        public static NotFound Instance { get; } = new();
    }
}

public sealed class EmailDeliveryException(Exception innerException) : Exception("Email delivery failed.", innerException);

public abstract record ConfirmResult
{
    public sealed record Success(User User) : ConfirmResult;

    public sealed record Invalid : ConfirmResult
    {
        public static Invalid Instance { get; } = new();
    }

    public sealed record Exhausted : ConfirmResult
    {
        public static Exhausted Instance { get; } = new();
    }
}
