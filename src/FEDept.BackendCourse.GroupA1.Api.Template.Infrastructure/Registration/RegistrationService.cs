using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class RegistrationService(AppDbContext db, IOptions<RegistrationOptions> options)
{
    public async Task<RegisterResult> RegisterAsync(string email, string password, CancellationToken ct)
    {
        var normalizedEmail = EmailNormalizer.Normalize(email);
        if (await db.Users.AnyAsync(user => user.Email == normalizedEmail, ct))
        {
            return NeutralResult();
        }

        if (options.Value.ConfirmationEnabled)
        {
            throw new NotSupportedException("Confirmation-enabled registration is added in a later task.");
        }

        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = normalizedEmail,
            PasswordHash = PasswordHasher.Hash(password),
            Status = UserStatus.Active,
            CreatedAt = now,
            UpdatedAt = now
        };

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        try
        {
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            return new RegisterResult.Active(user.Id, user.Email);
        }
        catch (DbUpdateException exception) when (
            exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            await transaction.RollbackAsync(ct);
            return NeutralResult();
        }
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
