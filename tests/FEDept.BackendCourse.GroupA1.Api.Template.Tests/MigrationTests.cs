using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests;

public sealed class MigrationTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    [Fact]
    public async Task Migrations_Apply_And_UsersTable_Exists()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.True(await db.Database.CanConnectAsync());
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task LoginChallenges_AllowOnlyOneUnconsumedAttemptPerUser()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = DateTimeOffset.UtcNow;
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = $"migration-{Guid.NewGuid():N}@example.com",
            PasswordHash = "hash",
            Status = UserStatus.Active,
            CreatedAt = now,
            UpdatedAt = now
        };
        LoginChallenge Challenge(DateTimeOffset? consumedAt) => new()
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Method = ChallengeMethod.Otp,
            SecretHash = "hash",
            LastSentAt = now,
            CreatedAt = now,
            ConsumedAt = consumedAt,
            ConsumedReason = consumedAt is null ? null : ConsumedReason.Replaced
        };
        db.Users.Add(user);
        db.LoginChallenges.AddRange(Challenge(now), Challenge(now), Challenge(null));
        await db.SaveChangesAsync();

        db.LoginChallenges.Add(Challenge(null));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }
}
