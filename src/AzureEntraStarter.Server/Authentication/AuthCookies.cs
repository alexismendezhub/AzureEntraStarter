using System.Security.Cryptography;
using System.Text;

namespace AzureEntraStarter.Server.Authentication;

/// <summary>
/// The browser session: an HttpOnly refresh cookie plus a readable XSRF cookie (double-submit). Both carry the
/// <c>__Host-</c> prefix (Secure, host-only, Path=/) and SameSite=Strict. Rename them here and in the Angular client
/// (<c>auth.constants.ts</c>) together.
/// </summary>
internal static class AuthCookies
{
    public const string RefreshCookieName = "__Host-aes_refresh";
    public const string XsrfCookieName = "__Host-aes_xsrf";
    public const string XsrfHeaderName = "X-AES-XSRF-TOKEN";
    /// <summary>Holds Microsoft's answer for at most five minutes, between the callback and the completion step.</summary>
    public const string ExternalCookieName = "__Host-aes_external";

    public static string CurrentOrigin(HttpContext http) => $"{http.Request.Scheme}://{http.Request.Host.Value}".TrimEnd('/');

    /// <summary>Rejects cross-site requests: Sec-Fetch-Site must not be cross-site and a present Origin must be this host's own.</summary>
    public static bool OriginMatchesCurrentHost(HttpContext http, bool requireOrigin)
    {
        var fetchSite = http.Request.Headers["Sec-Fetch-Site"].ToString();
        if (string.Equals(fetchSite, "cross-site", StringComparison.OrdinalIgnoreCase)) return false;
        var origin = http.Request.Headers.Origin.ToString().Trim().TrimEnd('/');
        if (string.IsNullOrWhiteSpace(origin)) return !requireOrigin;
        return string.Equals(origin, CurrentOrigin(http), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Double-submit check: the XSRF header must equal the XSRF cookie (constant-time comparison).</summary>
    public static bool ValidXsrf(HttpContext http)
    {
        if (!http.Request.Cookies.TryGetValue(XsrfCookieName, out var cookie) || string.IsNullOrWhiteSpace(cookie)) return false;
        var header = http.Request.Headers[XsrfHeaderName].ToString();
        if (string.IsNullOrWhiteSpace(header)) return false;
        var a = Encoding.UTF8.GetBytes(cookie);
        var b = Encoding.UTF8.GetBytes(header);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    public static void Write(HttpContext http, string rawRefresh, DateTime expiresAtUtc)
    {
        var expires = new DateTimeOffset(DateTime.SpecifyKind(expiresAtUtc, DateTimeKind.Utc));
        http.Response.Cookies.Append(RefreshCookieName, rawRefresh, Options(httpOnly: true, expires));
        // Hex: safe in a cookie and a header without any encoding.
        http.Response.Cookies.Append(XsrfCookieName, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), Options(httpOnly: false, expires));
    }

    public static void Clear(HttpContext http)
    {
        http.Response.Cookies.Delete(RefreshCookieName, Options(httpOnly: true, DateTimeOffset.UnixEpoch, TimeSpan.Zero));
        http.Response.Cookies.Delete(XsrfCookieName, Options(httpOnly: false, DateTimeOffset.UnixEpoch, TimeSpan.Zero));
    }

    private static CookieOptions Options(bool httpOnly, DateTimeOffset expires, TimeSpan? maxAge = null) =>
        new() { HttpOnly = httpOnly, Secure = true, SameSite = SameSiteMode.Strict, Path = "/", Expires = expires, MaxAge = maxAge, IsEssential = true };
}
