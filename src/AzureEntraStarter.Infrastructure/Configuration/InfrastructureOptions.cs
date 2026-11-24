using Microsoft.EntityFrameworkCore;

namespace AzureEntraStarter.Infrastructure.Configuration;

/// <summary>Configuration section <c>DataProtection</c>.</summary>
public sealed class DataProtectionSettings
{
    public const string Section = "DataProtection";
    /// <summary>Key Vault key that encrypts the key ring stored in SQL (for example https://my-vault.vault.azure.net/keys/dataprotection).</summary>
    public string KeyVaultKeyId { get; set; } = string.Empty;
}

/// <summary>Configuration section <c>Database</c>.</summary>
public sealed class DatabaseOptions
{
    public const string Section = "Database";
    public const string SqlServer = "SqlServer";
    public const string InMemory = "InMemory";

    /// <summary>SqlServer (LocalDB, SQL Server, Azure SQL) or InMemory (tests only).</summary>
    public string Provider { get; set; } = SqlServer;
    /// <summary>Name of the in-memory database (tests).</summary>
    public string Name { get; set; } = "AzureEntraStarter";
    /// <summary>Applies pending migrations at startup. Development only: production runs them from the pipeline.</summary>
    public bool MigrateOnStartup { get; set; }
}
