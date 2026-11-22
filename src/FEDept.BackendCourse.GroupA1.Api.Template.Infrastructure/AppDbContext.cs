using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Users;
using Microsoft.EntityFrameworkCore;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(user => user.Email)
            .IsUnique();

        modelBuilder.Entity<User>()
            .Property(user => user.Status)
            .HasConversion<string>();
    }
}
