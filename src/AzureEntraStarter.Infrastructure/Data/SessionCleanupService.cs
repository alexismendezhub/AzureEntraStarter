using Microsoft.EntityFrameworkCore;

namespace AzureEntraStarter.Infrastructure.Data;

/// <summary>Deletes used or expired sign-in tickets and ended sessions (with their refresh credentials) once a day has passed.</summary>
internal sealed class SessionCleanupService(IServiceScopeFactory scopes, TimeProvider time, ILogger<SessionCleanupService> logger) : BackgroundService
{
    private const int BatchSize = 500;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1), time);
        do
        {
            try { await RunOnceAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Session cleanup failed; it will run again in an hour.");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task<int> RunOnceAsync(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var cutoff = time.GetUtcNow().UtcDateTime.AddDays(-1);
        var removed = 0;
        while (true)
        {
            var tickets = await db.SignInTickets.Where(x => x.ExpiresAtUtc < cutoff).Take(BatchSize).ToListAsync(ct);
            var sessions = await db.UserSessions.Where(x => x.ExpiresAtUtc < cutoff || (x.RevokedAtUtc != null && x.RevokedAtUtc < cutoff)).Take(BatchSize).ToListAsync(ct);
            if (tickets.Count == 0 && sessions.Count == 0) break;
            var sessionIds = sessions.Select(s => s.Id).ToList();
            db.RefreshTokens.RemoveRange(await db.RefreshTokens.Where(x => sessionIds.Contains(x.SessionId)).ToListAsync(ct));
            db.SignInTickets.RemoveRange(tickets);
            db.UserSessions.RemoveRange(sessions);
            await db.SaveChangesAsync(ct);
            removed += tickets.Count + sessions.Count;
        }
        return removed;
    }
}
