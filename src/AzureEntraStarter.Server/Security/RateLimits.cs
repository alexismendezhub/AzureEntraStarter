using System.Threading.RateLimiting;

namespace AzureEntraStarter.Server.Security;

/// <summary>Per-IP limits on the sign-in and session endpoints (the rest of the API needs a valid session anyway).</summary>
internal static class RateLimits
{
    public const string Auth = "auth";
    public const string Session = "session";

    public static IServiceCollection AddAuthRateLimits(this IServiceCollection services, IConfiguration configuration)
    {
        var authPerMinute = configuration.GetValue("RateLimits:AuthPerMinute", 20);
        var sessionPerMinute = configuration.GetValue("RateLimits:SessionPerMinute", 60);
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.OnRejected = (context, _) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = "60";
                return ValueTask.CompletedTask;
            };
            o.AddPolicy(Auth, http => RateLimitPartition.GetFixedWindowLimiter(Key(http), _ => Window(authPerMinute)));
            o.AddPolicy(Session, http => RateLimitPartition.GetFixedWindowLimiter(Key(http), _ => Window(sessionPerMinute)));
        });
        return services;
    }

    private static string Key(HttpContext http) => http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static FixedWindowRateLimiterOptions Window(int permits) =>
        new() { PermitLimit = Math.Max(1, permits), Window = TimeSpan.FromMinutes(1), QueueLimit = 0 };
}
