namespace AzureEntraStarter.Domain.Users;

/// <summary>One signed-in browser. Access tokens carry its id (<c>sid</c>) and are honoured only while it is live.</summary>
public sealed class UserSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public AppUser? User { get; set; }
    /// <summary>The Entra app roles of the sign-in (JSON array), carried into every access token of the session.</summary>
    public string RolesJson { get; set; } = "[]";
    public DateTime AuthenticatedAtUtc { get; set; } = DateTime.UtcNow;
    /// <summary>Absolute end of the session (Session:MaxSessionHours after the sign-in).</summary>
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
}
