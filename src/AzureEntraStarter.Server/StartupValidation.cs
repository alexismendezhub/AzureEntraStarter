using AzureEntraStarter.Application.Authentication;
using AzureEntraStarter.Infrastructure.Configuration;
using AzureEntraStarter.Server.Authentication;

namespace AzureEntraStarter.Server;

/// <summary>Production refuses to start with a configuration that would be insecure or would not work with several instances.</summary>
internal static class StartupValidation
{
    public static IReadOnlyList<string> Check(IConfiguration configuration)
    {
        var errors = new List<string>();
        var entra = configuration.GetSection(EntraOptions.Section).Get<EntraOptions>() ?? new EntraOptions();
        if (!entra.IsConfigured)
            errors.Add("Authentication:Entra must be enabled and configured (Authority, ClientId and a client credential).");
        else
        {
            if (!EntraSecurity.IsSingleTenantAuthority(entra.Authority) && entra.AllowedTenantIds.All(string.IsNullOrWhiteSpace))
                errors.Add("A multi-tenant Authentication:Entra:Authority (organizations/common) requires Authentication:Entra:AllowedTenantIds.");
            if (entra.AllowPersonalAccounts)
                errors.Add("Authentication:Entra:AllowPersonalAccounts must be false in Production (consumer accounts are not managed by any organization).");
            if (entra.ClientCredentialType == EntraClientCredentialTypes.ClientSecret && entra.ClientSecret.Contains('<', StringComparison.Ordinal))
                errors.Add("Authentication:Entra:ClientSecret is still a placeholder.");
        }

        var jwt = configuration.GetSection(JwtOptions.Section).Get<JwtOptions>() ?? new JwtOptions();
        if (string.IsNullOrWhiteSpace(jwt.SigningKey))
            errors.Add("Jwt:SigningKey is required (a P-256 private key kept in Key Vault).");

        var database = configuration.GetSection(DatabaseOptions.Section).Get<DatabaseOptions>() ?? new DatabaseOptions();
        if (database.Provider != DatabaseOptions.SqlServer)
            errors.Add("Database:Provider must be SqlServer.");
        if (string.IsNullOrWhiteSpace(configuration.GetConnectionString("Default")))
            errors.Add("ConnectionStrings:Default is required.");
        if (database.MigrateOnStartup)
            errors.Add("Database:MigrateOnStartup must be false: run the migrations from the deployment pipeline.");

        var dataProtection = configuration.GetSection(DataProtectionSettings.Section).Get<DataProtectionSettings>() ?? new DataProtectionSettings();
        if (string.IsNullOrWhiteSpace(dataProtection.KeyVaultKeyId))
            errors.Add("DataProtection:KeyVaultKeyId is required: the key ring stored in SQL must be encrypted with a Key Vault key.");
        return errors;
    }

    public static void Validate(WebApplication app)
    {
        if (!app.Environment.IsProduction()) return;
        var errors = Check(app.Configuration);
        if (errors.Count > 0)
            throw new InvalidOperationException("Insecure production configuration:" + Environment.NewLine + " - " + string.Join(Environment.NewLine + " - ", errors));
    }
}
