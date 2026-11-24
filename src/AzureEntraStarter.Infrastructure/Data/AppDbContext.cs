using AzureEntraStarter.Domain.Users;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AzureEntraStarter.Infrastructure.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<SignInTicket> SignInTickets => Set<SignInTicket>();
    /// <summary>The Data Protection key ring, shared by every instance (it protects the sign-in round trip cookies).</summary>
    public DbSet<Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey> DataProtectionKeys => Set<Microsoft.AspNetCore.DataProtection.EntityFrameworkCore.DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.Entity<AppUser>(e =>
        {
            e.ToTable("Users");
            e.Property(x => x.EntraTenantId).HasMaxLength(36).IsRequired();
            e.Property(x => x.EntraObjectId).HasMaxLength(36).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(256);
            e.Property(x => x.Email).HasMaxLength(320);
            e.HasIndex(x => new { x.EntraTenantId, x.EntraObjectId }).IsUnique();
        });
        modelBuilder.Entity<UserSession>(e =>
        {
            e.ToTable("UserSessions");
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.Property(x => x.RolesJson).HasMaxLength(4000);
            e.HasIndex(x => x.UserId);
        });
        modelBuilder.Entity<RefreshToken>(e =>
        {
            e.ToTable("RefreshTokens");
            e.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.SessionId);
            e.HasOne<UserSession>().WithMany().HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.Cascade);
            e.Property(x => x.ConcurrencyStamp).IsConcurrencyToken();
        });
        modelBuilder.Entity<SignInTicket>(e =>
        {
            e.ToTable("SignInTickets");
            e.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.Property(x => x.RolesJson).HasMaxLength(4000);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.Property(x => x.ConcurrencyStamp).IsConcurrencyToken();
        });
    }
}
