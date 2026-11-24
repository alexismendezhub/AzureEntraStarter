using AzureEntraStarter.Infrastructure.Configuration;
using AzureEntraStarter.Infrastructure.Data;
using Azure.Identity;
using Microsoft.AspNetCore.DataProtection;

namespace AzureEntraStarter.Infrastructure;

public static class DependencyInjection
{
    /// <summary>Database, Data Protection key ring and the expired-session cleanup.</summary>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAppDatabase(configuration);
        services.AddHostedService<SessionCleanupService>();

        // Data Protection protects the OpenID Connect state/correlation cookies and the short-lived external cookie. Its key ring
        // lives in SQL (shared by every instance) and, when configured, is encrypted with an Azure Key Vault key.
        var dataProtection = services.AddDataProtection()
            .SetApplicationName("AzureEntraStarter")
            .PersistKeysToDbContext<AppDbContext>();
        var keyVaultKeyId = configuration[$"{DataProtectionSettings.Section}:KeyVaultKeyId"];
        if (!string.IsNullOrWhiteSpace(keyVaultKeyId))
            dataProtection.ProtectKeysWithAzureKeyVault(new Uri(keyVaultKeyId), new DefaultAzureCredential());

        return services;
    }
}
