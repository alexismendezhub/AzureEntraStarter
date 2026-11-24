namespace AzureEntraStarter.Domain.Users;

/// <summary>
/// A user of this application, identified ONLY by the immutable Microsoft Entra pair directory id (tid) + object id
/// (oid). The email and name are display data refreshed at each sign-in, never used to find the user.
/// </summary>
public sealed class AppUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string EntraTenantId { get; set; } = string.Empty;
    public string EntraObjectId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    /// <summary>A disabled user cannot sign in, and its open sessions stop on their next request.</summary>
    public bool Disabled { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastSignInAtUtc { get; set; }
}
