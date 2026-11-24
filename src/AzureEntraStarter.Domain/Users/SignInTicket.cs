namespace AzureEntraStarter.Domain.Users;

/// <summary>The one-time, short-lived ticket that hands a completed Microsoft sign-in to the browser (hash only).</summary>
public sealed class SignInTicket
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string TokenHash { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public string RolesJson { get; set; } = "[]";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? ConsumedAtUtc { get; set; }
    public Guid ConcurrencyStamp { get; set; } = Guid.NewGuid();
}
