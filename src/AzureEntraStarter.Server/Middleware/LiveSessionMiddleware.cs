using System.Security.Claims;
using AzureEntraStarter.Server.Authentication;

namespace AzureEntraStarter.Server.Middleware;

/// <summary>
/// Runs after authentication: an access token whose session was signed out, revoked or expired, or whose user was
/// disabled, stops working immediately instead of living until it expires. The request continues as anonymous, so the
/// deny-by-default policy answers 401 and the browser tries its refresh credential (which then fails too).
/// </summary>
internal sealed class LiveSessionMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, SessionService sessions)
    {
        if (context.User.Identity?.IsAuthenticated == true &&
            context.User.Identity.AuthenticationType != AuthenticationSchemes.External)
        {
            var sid = context.User.FindFirst("sid")?.Value;
            var sub = context.User.FindFirst("sub")?.Value;
            if (!Guid.TryParse(sid, out var sessionId) || !Guid.TryParse(sub, out var userId) ||
                !await sessions.IsLiveAsync(sessionId, userId, context.RequestAborted))
                context.User = new ClaimsPrincipal(new ClaimsIdentity());
        }
        await next(context);
    }
}
