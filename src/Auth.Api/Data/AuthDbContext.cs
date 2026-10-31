using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<AuthSession> Sessions => Set<AuthSession>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApplicationUser>().Property(x => x.DisplayName).HasMaxLength(100);
        builder.Entity<ApplicationUser>().HasIndex(x => x.NormalizedEmail).IsUnique();
        builder.Entity<AuthSession>().HasOne(x => x.User).WithMany()
            .HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        builder.Entity<RefreshToken>().Property(x => x.Hash).HasMaxLength(64);
        builder.Entity<RefreshToken>().HasIndex(x => x.Hash).IsUnique();
        builder.Entity<RefreshToken>().HasOne(x => x.Session).WithMany()
            .HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.Cascade);
    }
}
