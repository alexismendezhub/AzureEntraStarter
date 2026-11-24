using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Server.Authentication;

/// <summary>Validation of the Entra configuration and of every URL, path and issuer that crosses a trust boundary.</summary>
internal static class EntraSecurity
{
    public static Uri RequireHttpsUri(string value, string configurationKey)
    {
        if (!Uri.TryCreate(value?.Trim(), UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(uri.Host))
            throw new InvalidOperationException($"{configurationKey} must be an absolute HTTPS URI.");
        return uri;
    }

    public static void RequireSameAuthorityHost(Uri candidate, Uri authority, string configurationKey)
    {
        if (!SameAuthority(candidate, authority))
            throw new InvalidOperationException($"{configurationKey} must use the same HTTPS host and port as Authentication:Entra:Authority.");
    }

    public static string RequireCallbackPath(string value)
    {
        var path = (value ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('/') ||
            path.StartsWith("//", StringComparison.Ordinal) || path.Contains('\\') ||
            path.Contains('?') || path.Contains('#') || path.Any(char.IsControl))
            throw new InvalidOperationException("Authentication:Entra:CallbackPath must be a local application path without query/fragment content.");
        // The Angular dev-server proxy forwards the whole /api/ namespace to the server.
        if (!path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Authentication:Entra:CallbackPath must remain under /api/.");
        return path;
    }

    /// <summary>Open-redirect guard: only a local absolute path is ever used as a post-sign-in destination.</summary>
    public static string SafeLocalReturnPath(string? value, string fallback = "/")
    {
        var path = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('/') ||
            path.StartsWith("//", StringComparison.Ordinal) || path.StartsWith("/\\", StringComparison.Ordinal) ||
            path.Contains('\\') || path.Any(char.IsControl))
            return fallback;
        return path;
    }

    public static string CanonicalGuid(string value) =>
        Guid.TryParse(value?.Trim(), out var id) ? id.ToString("D") : throw new InvalidOperationException($"'{value}' is not a valid directory id.");

    /// <summary>The issuer must sit under the configured authority (same host and path shape).</summary>
    public static string ValidateIssuerForAuthority(string issuer, string configuredAuthority)
    {
        var authority = RequireHttpsUri(configuredAuthority, "Authentication:Entra:Authority");
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri) || issuerUri.Scheme != Uri.UriSchemeHttps)
            throw new SecurityTokenInvalidIssuerException("The Microsoft Entra token issuer is not a valid HTTPS URI.");
        if (!SameAuthority(issuerUri, authority) || !HasCompatibleAuthorityPath(issuerUri, authority))
            throw new SecurityTokenInvalidIssuerException("The Microsoft Entra token issuer does not match the configured authority.");
        return issuer;
    }

    /// <summary>
    /// The issuer must name the very directory in the token's immutable <c>tid</c> claim. With a multi-tenant authority
    /// (organizations/common) this is what stops a token of one directory from posing as another.
    /// </summary>
    public static bool IssuerMatchesTenant(string issuer, string tenantId, string configuredAuthority)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || !Guid.TryParse(tenantId, out var tenantGuid)) return false;
        var canonicalTenantId = tenantGuid.ToString("D");
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri) || issuerUri.Scheme != Uri.UriSchemeHttps) return false;
        if (!Uri.TryCreate(configuredAuthority, UriKind.Absolute, out var authorityUri) || authorityUri.Scheme != Uri.UriSchemeHttps) return false;
        if (!SameAuthority(issuerUri, authorityUri)) return false;

        var authoritySegments = PathSegments(authorityUri);
        var issuerSegments = PathSegments(issuerUri);
        if (authoritySegments.Length < 2 || issuerSegments.Length != authoritySegments.Length) return false;
        if (!string.Equals(issuerSegments[0], canonicalTenantId, StringComparison.OrdinalIgnoreCase)) return false;

        // A tenant-specific authority narrows sign-in to exactly that directory.
        if (Guid.TryParse(authoritySegments[0], out _) &&
            !string.Equals(authoritySegments[0], canonicalTenantId, StringComparison.OrdinalIgnoreCase)) return false;

        for (var i = 1; i < authoritySegments.Length; i++)
            if (!string.Equals(issuerSegments[i], authoritySegments[i], StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    /// <summary>True when the authority accepts a single directory (its first path segment is a directory id).</summary>
    public static bool IsSingleTenantAuthority(string configuredAuthority) =>
        Uri.TryCreate(configuredAuthority, UriKind.Absolute, out var uri) &&
        PathSegments(uri) is { Length: > 0 } segments && Guid.TryParse(segments[0], out _);

    private static bool HasCompatibleAuthorityPath(Uri issuer, Uri authority)
    {
        var authoritySegments = PathSegments(authority);
        var issuerSegments = PathSegments(issuer);
        if (authoritySegments.Length < 2 || issuerSegments.Length != authoritySegments.Length) return false;
        for (var i = 1; i < authoritySegments.Length; i++)
            if (!string.Equals(issuerSegments[i], authoritySegments[i], StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static bool SameAuthority(Uri left, Uri right) =>
        string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port;

    private static string[] PathSegments(Uri uri) =>
        uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
