using System.Security.Claims;
using AzureEntraStarter.Application.Authentication;
using AzureEntraStarter.Domain.Users;
using AzureEntraStarter.Infrastructure.Authentication;
using AzureEntraStarter.Infrastructure.Data;
using AzureEntraStarter.Server.Authentication;
using AzureEntraStarter.Server.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using static AzureEntraStarter.Server.Authentication.EntraSecurity;

namespace AzureEntraStarter.Server.Endpoints;

public sealed record ExchangeRequest(string? Ticket);

public sealed record AuthConfigResponse(bool EntraEnabled);

public sealed record LogoutResponse(string? MicrosoftSignOutUrl);

internal static class AuthEndpoints
{
    public static WebApplication MapAuthEndpoints(this WebApplication app)
    {
        var entra = app.Services.GetRequiredService<IOptions<EntraOptions>>().Value;
        var auth = app.MapGroup("/api/auth");

        // What the sign-in page can offer.
        auth.MapGet("/config", () => Results.Ok(new AuthConfigResponse(entra.IsConfigured))).AllowAnonymous();

        // The application's public signing keys, for other services that verify its access tokens.
        app.MapGet("/.well-known/jwks.json", (TokenSigningKeys keys) => Results.Json(new { keys = keys.PublicKeys }))
            .AllowAnonymous();

        if (entra.IsConfigured)
        {
            // Starts the OpenID Connect round trip (authorization code + PKCE, state and nonce owned by the handler).
            auth.MapGet("/entra/start", (string? returnUrl, string? prompt) =>
            {
                var safeReturn = SafeLocalReturnPath(returnUrl);
                var props = new AuthenticationProperties { RedirectUri = "/api/auth/entra/complete" };
                props.Items[SsoProperties.ReturnUrl] = safeReturn;
                if (prompt is "login" or "select_account") props.Items[SsoProperties.Prompt] = prompt;
                return Results.Challenge(props, [AuthenticationSchemes.Entra]);
            }).RequireRateLimiting(RateLimits.Auth).AllowAnonymous();

            // Back from Microsoft: map the immutable tid+oid to one local user and hand the browser a single-use ticket in
            // the URL fragment (never a token, never in the query string, so it does not reach logs or the Referer).
            auth.MapGet("/entra/complete", async (HttpContext http, AppDbContext db, SessionService sessions, TimeProvider time) =>
            {
                var external = await http.AuthenticateAsync(AuthenticationSchemes.External);
                await http.SignOutAsync(AuthenticationSchemes.External);
                var principal = external.Principal;
                if (!external.Succeeded || principal is null) return Results.Redirect("/login?ssoError=" + SsoErrorCodes.SessionExpired);

                if (!Guid.TryParse(principal.FindFirst("tid")?.Value, out var tidGuid) || !Guid.TryParse(principal.FindFirst("oid")?.Value, out var oidGuid))
                    return Results.Redirect("/login?ssoError=" + SsoErrorCodes.Failed);
                var tid = tidGuid.ToString("D");
                var oid = oidGuid.ToString("D");
                var displayName = Bounded(principal.FindFirst("name")?.Value, 256);
                // Mutable email/preferred_username are display data only; the identity is tid+oid.
                var email = Bounded(principal.FindFirst("email")?.Value ?? principal.FindFirst("preferred_username")?.Value, 320);
                var roles = SessionService.NormalizeRoles(principal.FindAll("roles").Select(c => c.Value));

                var user = await db.Users.FirstOrDefaultAsync(x => x.EntraTenantId == tid && x.EntraObjectId == oid);
                if (user is null)
                {
                    if (!entra.AutoProvisionUsers) return Results.Redirect("/login?ssoError=" + SsoErrorCodes.NotRegistered);
                    user = new AppUser { EntraTenantId = tid, EntraObjectId = oid, CreatedAtUtc = time.GetUtcNow().UtcDateTime };
                    db.Users.Add(user);
                }
                if (user.Disabled) return Results.Redirect("/login?ssoError=" + SsoErrorCodes.NotAllowed);
                user.DisplayName = displayName;
                user.Email = email;
                try { await db.SaveChangesAsync(); }
                catch (DbUpdateException)
                {
                    // The same person finished two sign-ins at once and the other one created the user first.
                    db.ChangeTracker.Clear();
                    user = await db.Users.FirstAsync(x => x.EntraTenantId == tid && x.EntraObjectId == oid);
                }

                var ticket = await sessions.CreateTicketAsync(user, roles, http.RequestAborted);
                var returnUrl = external.Properties?.Items.TryGetValue(SsoProperties.ReturnUrl, out var r) == true ? SafeLocalReturnPath(r) : "/";
                return Results.Redirect($"/login#ticket={Uri.EscapeDataString(ticket)}&returnUrl={Uri.EscapeDataString(returnUrl)}");
            }).AllowAnonymous();

            // The browser exchanges the one-time ticket for its session (access token + refresh cookie on this host).
            auth.MapPost("/entra/exchange", async (HttpContext http, ExchangeRequest request, SessionService sessions) =>
            {
                if (!AuthCookies.OriginMatchesCurrentHost(http, requireOrigin: true)) return Results.StatusCode(StatusCodes.Status403Forbidden);
                var consumed = await sessions.ConsumeTicketAsync(request.Ticket ?? string.Empty, http.RequestAborted);
                if (consumed is null) return Results.Unauthorized();
                return Results.Ok(await sessions.StartSessionAsync(http, consumed.Value.User, consumed.Value.Roles, http.RequestAborted));
            }).RequireRateLimiting(RateLimits.Auth).AllowAnonymous();
        }

        // Rotates the refresh credential and issues a new access token. The only request authenticated by a cookie, so it
        // requires this host's own Origin and the XSRF double-submit header.
        auth.MapPost("/refresh", async (HttpContext http, SessionService sessions) =>
        {
            if (!AuthCookies.OriginMatchesCurrentHost(http, requireOrigin: true) || !AuthCookies.ValidXsrf(http)) return Results.StatusCode(StatusCodes.Status403Forbidden);
            if (!http.Request.Cookies.TryGetValue(AuthCookies.RefreshCookieName, out var raw) || string.IsNullOrWhiteSpace(raw))
            {
                AuthCookies.Clear(http);
                return Results.NoContent();
            }
            var result = await sessions.RefreshAsync(http, raw, http.RequestAborted);
            switch (result.Status)
            {
                case RefreshStatus.Renewed: return Results.Ok(result.Response);
                case RefreshStatus.AlreadyRotated: return Results.NoContent();
                default:
                    AuthCookies.Clear(http);
                    return Results.NoContent();
            }
        }).RequireRateLimiting(RateLimits.Session).AllowAnonymous();

        auth.MapPost("/logout", async (HttpContext http, SessionService sessions, IOptionsMonitor<OpenIdConnectOptions> oidc) =>
        {
            // Logout always clears the browser cookies. A present refresh credential is revoked only with Origin + XSRF.
            AppUser? user = null;
            if (http.Request.Cookies.TryGetValue(AuthCookies.RefreshCookieName, out var raw) && !string.IsNullOrWhiteSpace(raw))
            {
                if (!AuthCookies.OriginMatchesCurrentHost(http, requireOrigin: true) || !AuthCookies.ValidXsrf(http)) return Results.StatusCode(StatusCodes.Status403Forbidden);
                user = await sessions.RevokeAsync(raw, http.RequestAborted);
            }
            AuthCookies.Clear(http);
            if (!entra.IsConfigured || !entra.SignOutOfMicrosoft || user is null) return Results.Ok(new LogoutResponse(null));
            // Front-channel sign-out at Microsoft (end_session_endpoint from discovery), back to /signed-out.
            var options = oidc.Get(AuthenticationSchemes.Entra);
            var configuration = await options.ConfigurationManager!.GetConfigurationAsync(http.RequestAborted);
            if (string.IsNullOrWhiteSpace(configuration.EndSessionEndpoint)) return Results.Ok(new LogoutResponse(null));
            var url = QueryHelpers.AddQueryString(configuration.EndSessionEndpoint, new Dictionary<string, string?>
            {
                ["client_id"] = entra.ClientId,
                ["post_logout_redirect_uri"] = AuthCookies.CurrentOrigin(http) + "/signed-out"
            });
            return Results.Ok(new LogoutResponse(url));
        }).RequireRateLimiting(RateLimits.Session).AllowAnonymous();

        // The signed-in user, from the access token (the session was already checked live by LiveSessionMiddleware).
        auth.MapGet("/me", (ClaimsPrincipal principal) => Results.Ok(new UserInfo(
            Guid.Parse(principal.FindFirst("sub")!.Value),
            principal.FindFirst("name")?.Value ?? string.Empty,
            principal.FindFirst("email")?.Value ?? string.Empty,
            principal.FindFirst("tid")?.Value ?? string.Empty,
            principal.FindFirst("oid")?.Value ?? string.Empty,
            principal.FindAll("role").Select(c => c.Value).ToList())));

        return app;
    }

    private static string Bounded(string? value, int max)
    {
        var text = (value ?? string.Empty).Trim();
        return text.Length <= max ? text : text[..max];
    }
}
