using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    public DbSet<RegistrationChallenge> RegistrationChallenges => Set<RegistrationChallenge>();

    public DbSet<LoginChallenge> LoginChallenges => Set<LoginChallenge>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(user => user.Email)
            .IsUnique();

        modelBuilder.Entity<User>()
            .Property(user => user.Status)
            .HasConversion<string>();

        modelBuilder.Entity<RegistrationChallenge>(entity =>
        {
            entity.ToTable("registration_challenges");
            entity.Property(challenge => challenge.Id).HasColumnName("id");
            entity.Property(challenge => challenge.UserId).HasColumnName("user_id");
            entity.Property(challenge => challenge.Method).HasColumnName("method").HasConversion<string>();
            entity.Property(challenge => challenge.SecretHash).HasColumnName("secret_hash");
            entity.Property(challenge => challenge.ExpiresAt).HasColumnName("expires_at");
            entity.Property(challenge => challenge.Attempts).HasColumnName("attempts");
            entity.Property(challenge => challenge.LastSentAt).HasColumnName("last_sent_at");
            entity.Property(challenge => challenge.ConsumedAt).HasColumnName("consumed_at");
            entity.HasIndex(challenge => challenge.SecretHash);
            entity.HasOne<User>().WithMany().HasForeignKey(challenge => challenge.UserId);
        });

        modelBuilder.Entity<LoginChallenge>(entity =>
        {
            entity.ToTable("login_challenges");
            entity.Property(challenge => challenge.Id).HasColumnName("id");
            entity.Property(challenge => challenge.UserId).HasColumnName("user_id");
            entity.Property(challenge => challenge.Method).HasColumnName("method").HasConversion<string>();
            entity.Property(challenge => challenge.SecretHash).HasColumnName("secret_hash");
            entity.Property(challenge => challenge.LastSentAt).HasColumnName("last_sent_at");
            entity.Property(challenge => challenge.Attempts).HasColumnName("attempts");
            entity.Property(challenge => challenge.ConsumedAt).HasColumnName("consumed_at");
            entity.Property(challenge => challenge.ConsumedReason).HasColumnName("consumed_reason").HasConversion<string>();
            entity.Property(challenge => challenge.CreatedAt).HasColumnName("created_at");
            entity.HasIndex(challenge => challenge.UserId)
                .IsUnique()
                .HasFilter("\"consumed_at\" IS NULL");
            entity.HasOne<User>().WithMany().HasForeignKey(challenge => challenge.UserId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
