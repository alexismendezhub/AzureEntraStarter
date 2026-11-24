using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace AzureEntraStarter.Application.Authentication;

public sealed record UserInfo(Guid Id, string DisplayName, string Email, string TenantId, string ObjectId, IReadOnlyList<string> Roles);

public sealed record AuthResponse(string AccessToken, DateTime ExpiresAtUtc, DateTime SessionExpiresAtUtc, UserInfo User);

public enum RefreshStatus
{
    /// <summary>A new access token was issued and the refresh credential rotated.</summary>
    Renewed,
    /// <summary>No usable session: the cookies are cleared and the browser must sign in.</summary>
    SignedOut,
    /// <summary>Another tab rotated this credential a moment ago: nothing changes and the cookies are left alone.</summary>
    AlreadyRotated
}

public sealed record RefreshResult(RefreshStatus Status, AuthResponse? Response = null);
