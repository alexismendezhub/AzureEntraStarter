namespace AzureEntraStarter.Domain.Users;

/// <summary>A refresh credential: only its SHA-256 is stored. Each use rotates it; a rotated one used again ends the session.</summary>
public sealed class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SessionId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RotatedAtUtc { get; set; }
    /// <summary>Changes on every update, so two requests cannot both rotate (or both consume) the same row.</summary>
    public Guid ConcurrencyStamp { get; set; } = Guid.NewGuid();
}
