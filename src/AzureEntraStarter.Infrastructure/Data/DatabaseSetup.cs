using AzureEntraStarter.Infrastructure.Configuration;
using Microsoft.EntityFrameworkCore;

namespace AzureEntraStarter.Infrastructure.Data;

public static class DatabaseSetup
{
    public static IServiceCollection AddAppDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(DatabaseOptions.Section).Get<DatabaseOptions>() ?? new DatabaseOptions();
        services.Configure<DatabaseOptions>(configuration.GetSection(DatabaseOptions.Section));
        services.AddDbContext<AppDbContext>(db =>
        {
            if (options.Provider == DatabaseOptions.InMemory)
            {
                db.UseInMemoryDatabase(options.Name);
                return;
            }
            var connectionString = configuration.GetConnectionString("Default");
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new InvalidOperationException("ConnectionStrings:Default is required with Database:Provider = SqlServer.");
            db.UseSqlServer(connectionString, sql => sql.EnableRetryOnFailure());
        });
        services.AddHealthChecks().AddDbContextCheck<AppDbContext>("database", tags: ["ready"]);
        return services;
    }

    public static async Task PrepareDatabaseAsync(this WebApplication app)
    {
        var options = app.Configuration.GetSection(DatabaseOptions.Section).Get<DatabaseOptions>() ?? new DatabaseOptions();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        if (options.Provider == DatabaseOptions.InMemory)
            await db.Database.EnsureCreatedAsync();
        else if (options.MigrateOnStartup)
            await db.Database.MigrateAsync();
    }
}
