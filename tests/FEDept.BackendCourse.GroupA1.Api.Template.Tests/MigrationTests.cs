using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure;
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
}
