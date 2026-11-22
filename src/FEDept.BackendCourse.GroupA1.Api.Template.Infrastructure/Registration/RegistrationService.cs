using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class RegistrationService(
    AppDbContext db,
    IOptions<RegistrationOptions> options,
    IEmailSender emailSender)
{
    public async Task<RegisterResult> RegisterAsync(string email, string password, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        if (await db.Users.AnyAsync(user => user.Email == normalizedEmail, ct))
        {
            return NeutralResult();
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
        var code = confirmationEnabled ? OtpGenerator.Generate() : null;
        var challenge = confirmationEnabled
            ? new RegistrationChallenge
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Method = ChallengeMethod.Otp,
                SecretHash = new SecretHasher(options.Value.HmacKey).Hash(code!),
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

            if (code is not null)
            {
                await emailSender.SendOtpAsync(normalizedEmail, code, ct);
                return new RegisterResult.ConfirmationRequired(challenge!.Id);
            }

            return new RegisterResult.Active(user.Id, user.Email);
        }
        catch (DbUpdateException exception) when (
            exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            await transaction.RollbackAsync(ct);
            return NeutralResult();
        }
    }

    public async Task<ConfirmResult> ConfirmAsync(Guid attemptId, string code, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var challenge = await db.RegistrationChallenges.SingleOrDefaultAsync(item => item.Id == attemptId, ct);
        if (challenge is null || challenge.ConsumedAt is not null)
        {
            return ConfirmResult.Invalid.Instance;
        }

        var now = DateTimeOffset.UtcNow;
        if (challenge.ExpiresAt <= now)
        {
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
                return ConfirmResult.Exhausted.Instance;
            }

            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            return ConfirmResult.Invalid.Instance;
        }

        var user = await db.Users.SingleAsync(item => item.Id == challenge.UserId, ct);
        user.Status = UserStatus.Active;
        user.UpdatedAt = now;
        challenge.ConsumedAt = now;
        // shortcut: assign user role here once RBAC module exists
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return new ConfirmResult.Success(user);
    }

    private static RegisterResult.ConfirmationRequired NeutralResult()
    {
        // shortcut: Task 6 replaces this placeholder attemptId with a real persisted decoy challenge so confirm stays indistinguishable
        return new RegisterResult.ConfirmationRequired(Guid.NewGuid());
    }
}

public abstract record RegisterResult
{
    public sealed record Active(Guid Id, string Email) : RegisterResult;

    public sealed record ConfirmationRequired(Guid AttemptId) : RegisterResult;
}

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
