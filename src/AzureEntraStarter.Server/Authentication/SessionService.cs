using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AzureEntraStarter.Application.Authentication;
using AzureEntraStarter.Domain.Users;
using AzureEntraStarter.Infrastructure.Authentication;
using AzureEntraStarter.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using SessionOptions = AzureEntraStarter.Application.Authentication.SessionOptions;
namespace AzureEntraStarter.Server.Authentication;

/// <summary>
/// The application's own session after a Microsoft sign-in: a one-time ticket, then a short ES256 access token (kept in
/// memory by the browser) and a rotating HttpOnly refresh credential (only its hash is stored).
/// </summary>
internal sealed class SessionService(AppDbContext db, TokenSigningKeys keys, IOptions<JwtOptions> jwtOptions, IOptions<SessionOptions> sessionOptions, TimeProvider time)
{
    private const int MaxRoles = 50;
    private const int MaxRoleLength = 120;
    private readonly JwtOptions _jwt = jwtOptions.Value;
    private readonly SessionOptions _session = sessionOptions.Value;

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string NewSecret() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    /// <summary>Entra app roles of the sign-in, bounded so a crafted or huge claim cannot overflow the session row.</summary>
    public static IReadOnlyList<string> NormalizeRoles(IEnumerable<string> roles) => roles
        .Select(r => r.Trim())
        .Where(r => r.Length is > 0 and <= MaxRoleLength && !r.Any(char.IsControl))
        .Distinct(StringComparer.Ordinal)
        .Take(MaxRoles)
        .ToList();

    public async Task<string> CreateTicketAsync(AppUser user, IReadOnlyList<string> roles, CancellationToken ct)
    {
        var raw = NewSecret();
        db.SignInTickets.Add(new SignInTicket
        {
            TokenHash = Hash(raw),
            UserId = user.Id,
            RolesJson = JsonSerializer.Serialize(roles),
            CreatedAtUtc = Now,
            ExpiresAtUtc = Now.AddSeconds(Math.Clamp(_session.SignInTicketSeconds, 30, 300))
        });
        await db.SaveChangesAsync(ct);
        return raw;
    }

    /// <summary>Consumes a ticket exactly once (concurrency-checked). Null when unknown, used, expired or the user is disabled.</summary>
    public async Task<(AppUser User, IReadOnlyList<string> Roles)?> ConsumeTicketAsync(string rawTicket, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rawTicket) || rawTicket.Length > 128) return null;
        var hash = Hash(rawTicket.Trim());
        var ticket = await db.SignInTickets.FirstOrDefaultAsync(x => x.TokenHash == hash, ct);
        if (ticket is null || ticket.ConsumedAtUtc is not null || ticket.ExpiresAtUtc <= Now) return null;
        ticket.ConsumedAtUtc = Now;
        ticket.ConcurrencyStamp = Guid.NewGuid();
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return null; }
        var user = await db.Users.FirstOrDefaultAsync(x => x.Id == ticket.UserId, ct);
        if (user is null || user.Disabled) return null;
        return (user, JsonSerializer.Deserialize<List<string>>(ticket.RolesJson) ?? []);
    }

    public async Task<AuthResponse> StartSessionAsync(HttpContext http, AppUser user, IReadOnlyList<string> roles, CancellationToken ct)
    {
        // A new sign-in in this browser ends the session it had before.
        if (http.Request.Cookies.TryGetValue(AuthCookies.RefreshCookieName, out var prior) && !string.IsNullOrWhiteSpace(prior))
            await RevokeAsync(prior, ct);

        var session = new UserSession
        {
            UserId = user.Id,
            RolesJson = JsonSerializer.Serialize(roles),
            AuthenticatedAtUtc = Now,
            ExpiresAtUtc = Now.AddHours(Math.Clamp(_session.MaxSessionHours, 1, 24 * 7))
        };
        db.UserSessions.Add(session);
        user.LastSignInAtUtc = Now;
        var raw = AddRefreshToken(session);
        await db.SaveChangesAsync(ct);
        return Issue(http, user, session, roles, raw.Raw, raw.ExpiresAtUtc);
    }

    public async Task<RefreshResult> RefreshAsync(HttpContext http, string rawRefresh, CancellationToken ct)
    {
        var hash = Hash(rawRefresh);
        var token = await db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, ct);
        if (token is null) return new(RefreshStatus.SignedOut);
        var session = await db.UserSessions.Include(x => x.User).FirstOrDefaultAsync(x => x.Id == token.SessionId, ct);
        if (session?.User is null) return new(RefreshStatus.SignedOut);

        if (token.RotatedAtUtc is { } rotatedAt)
        {
            // Another tab rotated it a moment ago: harmless. Later: a stolen copy is being replayed, so the session ends.
            if (Now - rotatedAt <= TimeSpan.FromSeconds(Math.Clamp(_session.ReuseGraceSeconds, 0, 120))) return new(RefreshStatus.AlreadyRotated);
            session.RevokedAtUtc ??= Now;
            await db.SaveChangesAsync(ct);
            return new(RefreshStatus.SignedOut);
        }
        if (token.ExpiresAtUtc <= Now || session.RevokedAtUtc is not null || session.ExpiresAtUtc <= Now || session.User.Disabled)
        {
            session.RevokedAtUtc ??= Now;
            await db.SaveChangesAsync(ct);
            return new(RefreshStatus.SignedOut);
        }

        token.RotatedAtUtc = Now;
        token.ConcurrencyStamp = Guid.NewGuid();
        var next = AddRefreshToken(session);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return new(RefreshStatus.AlreadyRotated); }
        var roles = JsonSerializer.Deserialize<List<string>>(session.RolesJson) ?? [];
        return new(RefreshStatus.Renewed, Issue(http, session.User, session, roles, next.Raw, next.ExpiresAtUtc));
    }

    /// <summary>Ends the session that owns this refresh credential. Returns the session's user, if any.</summary>
    public async Task<AppUser?> RevokeAsync(string rawRefresh, CancellationToken ct)
    {
        var hash = Hash(rawRefresh);
        var token = await db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, ct);
        if (token is null) return null;
        var session = await db.UserSessions.Include(x => x.User).FirstOrDefaultAsync(x => x.Id == token.SessionId, ct);
        if (session is null) return null;
        session.RevokedAtUtc ??= Now;
        await db.SaveChangesAsync(ct);
        return session.User;
    }

    /// <summary>An access token is honoured only while its session is live and its user enabled (checked on every request).</summary>
    public Task<bool> IsLiveAsync(Guid sessionId, Guid userId, CancellationToken ct) =>
        db.UserSessions.AsNoTracking().AnyAsync(x => x.Id == sessionId && x.UserId == userId && x.RevokedAtUtc == null && x.ExpiresAtUtc > Now && !x.User!.Disabled, ct);

    private (string Raw, DateTime ExpiresAtUtc) AddRefreshToken(UserSession session)
    {
        var raw = NewSecret();
        var idle = Now.AddMinutes(Math.Clamp(_session.RefreshTokenMinutes, 5, 24 * 60));
        var expires = idle < session.ExpiresAtUtc ? idle : session.ExpiresAtUtc;
        db.RefreshTokens.Add(new RefreshToken { SessionId = session.Id, TokenHash = Hash(raw), CreatedAtUtc = Now, ExpiresAtUtc = expires });
        return (raw, expires);
    }

    private AuthResponse Issue(HttpContext http, AppUser user, UserSession session, IReadOnlyList<string> roles, string rawRefresh, DateTime refreshExpiresAtUtc)
    {
        var accessExpires = Now.AddMinutes(Math.Clamp(_jwt.AccessTokenMinutes, 1, 60));
        if (accessExpires > session.ExpiresAtUtc) accessExpires = session.ExpiresAtUtc;
        var claims = new List<Claim>
        {
            new("sub", user.Id.ToString("D")),
            new("sid", session.Id.ToString("D")),
            new("name", user.DisplayName),
            new("email", user.Email),
            new("tid", user.EntraTenantId),
            new("oid", user.EntraObjectId),
            new("auth_time", new DateTimeOffset(session.AuthenticatedAtUtc).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            new("jti", Guid.NewGuid().ToString("N"))
        };
        claims.AddRange(roles.Select(r => new Claim("role", r)));
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _jwt.Issuer,
            Audience = _jwt.Audience,
            Subject = new ClaimsIdentity(claims),
            NotBefore = Now,
            IssuedAt = Now,
            Expires = accessExpires,
            SigningCredentials = keys.SigningCredentials
        });
        AuthCookies.Write(http, rawRefresh, refreshExpiresAtUtc);
        return new AuthResponse(token, accessExpires, session.ExpiresAtUtc, ToInfo(user, roles));
    }

    public static UserInfo ToInfo(AppUser user, IReadOnlyList<string> roles) =>
        new(user.Id, user.DisplayName, user.Email, user.EntraTenantId, user.EntraObjectId, roles);
}
