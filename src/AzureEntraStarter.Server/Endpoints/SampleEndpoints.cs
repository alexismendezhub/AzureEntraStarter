using System.Security.Claims;
using AzureEntraStarter.Infrastructure.Data;
using AzureEntraStarter.Server.Authentication;
using Microsoft.EntityFrameworkCore;

namespace AzureEntraStarter.Server.Endpoints;

/// <summary>Examples of protected endpoints: any signed-in user, and users with the Entra app role "Admin".</summary>
internal static class SampleEndpoints
{
    public static WebApplication MapSampleEndpoints(this WebApplication app)
    {
        // No attribute needed: the fallback policy already requires a signed-in user with a live session.
        app.MapGet("/api/sample/hello", (ClaimsPrincipal user) =>
            Results.Ok(new { message = $"Hello, {user.FindFirst("name")?.Value}. This answer required a valid session." }));

        var admin = app.MapGroup("/api/admin").RequireAuthorization(AppRoles.Admin);
        admin.MapGet("/users", async (AppDbContext db) => Results.Ok(await db.Users.AsNoTracking()
            .OrderBy(x => x.DisplayName)
            .Take(200)
            .Select(x => new { x.Id, x.DisplayName, x.Email, tenantId = x.EntraTenantId, x.Disabled, x.LastSignInAtUtc })
            .ToListAsync()));

        // Disabling a user ends its sessions at once (LiveSessionMiddleware) and blocks its next sign-in.
        admin.MapPost("/users/{id:guid}/disabled", async (Guid id, DisableRequest request, AppDbContext db, ClaimsPrincipal caller) =>
        {
            if (caller.FindFirst("sub")?.Value == id.ToString("D") && request.Disabled)
                return Results.BadRequest(new { message = "You cannot disable your own account." });
            var user = await db.Users.FirstOrDefaultAsync(x => x.Id == id);
            if (user is null) return Results.NotFound();
            user.Disabled = request.Disabled;
            await db.SaveChangesAsync();
            return Results.NoContent();
        });
        return app;
    }
}

public sealed record DisableRequest(bool Disabled);
