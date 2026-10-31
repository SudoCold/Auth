using Auth.Api.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Data;

public static class DatabaseInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, IConfiguration config)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        if (config.GetValue<bool>("Database:MigrateOnStartup"))
            await db.Database.MigrateAsync();

        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var role in Roles.All)
            if (!await roles.RoleExistsAsync(role)) Ensure(await roles.CreateAsync(new IdentityRole(role)));

        var email = config["BootstrapAdmin:Email"]?.Trim();
        var password = config["BootstrapAdmin:Password"];
        if (string.IsNullOrWhiteSpace(email) && string.IsNullOrWhiteSpace(password)) return;
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Set both BootstrapAdmin:Email and BootstrapAdmin:Password.");

        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByEmailAsync(email);
        if (user is not null)
        {
            if (!await users.IsInRoleAsync(user, Roles.Admin))
                throw new InvalidOperationException("Bootstrap email already belongs to a non-administrator. Use a new email.");
            return;
        }

        await using var transaction = await db.Database.BeginTransactionAsync();
        user = new ApplicationUser { UserName = email, Email = email, DisplayName = "Administrator" };
        Ensure(await users.CreateAsync(user, password));
        Ensure(await users.AddToRolesAsync(user, Roles.All));
        await transaction.CommitAsync();
    }

    private static void Ensure(IdentityResult result)
    {
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(" ", result.Errors.Select(x => x.Description)));
    }
}
