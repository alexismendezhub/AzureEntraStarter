using System.Security.Cryptography;
using AzureEntraStarter.Server;
using AzureEntraStarter.Server.Authentication;
using AzureEntraStarter.Server.IntegrationTests.Support;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Server.IntegrationTests;

public sealed class EntraSecurityTests
{
    private const string TenantAuthority = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";
    private const string OrganizationsAuthority = "https://login.microsoftonline.com/organizations/v2.0";

    [Theory]
    [InlineData("/profile", "/profile")]
    [InlineData("/a/b?c=d", "/a/b?c=d")]
    [InlineData(null, "/")]
    [InlineData("", "/")]
    [InlineData("profile", "/")]
    [InlineData("//evil.example", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("/a\\b", "/")]
    [InlineData("https://evil.example/", "/")]
    [InlineData("/a\nb", "/")]
    public void Only_local_paths_are_return_urls(string? value, string expected) =>
        Assert.Equal(expected, EntraSecurity.SafeLocalReturnPath(value));

    [Theory]
    [InlineData("/api/auth/oidc/callback", true)]
    [InlineData("/signin-oidc", false)]
    [InlineData("api/auth/cb", false)]
    [InlineData("//api/auth/cb", false)]
    [InlineData("/api/auth/cb?x=1", false)]
    [InlineData("/api/auth/cb#x", false)]
    public void The_callback_stays_a_plain_path_under_api(string path, bool valid)
    {
        if (valid) Assert.Equal(path, EntraSecurity.RequireCallbackPath(path));
        else Assert.Throws<InvalidOperationException>(() => EntraSecurity.RequireCallbackPath(path));
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0", "11111111-1111-1111-1111-111111111111", TenantAuthority, true)]
    [InlineData("https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0", "22222222-2222-2222-2222-222222222222", TenantAuthority, false)]
    [InlineData("https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0", "22222222-2222-2222-2222-222222222222", OrganizationsAuthority, true)]
    [InlineData("https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0", "22222222-2222-2222-2222-222222222222", OrganizationsAuthority, false)]
    [InlineData("https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/", "22222222-2222-2222-2222-222222222222", OrganizationsAuthority, false)]
    [InlineData("https://evil.example/22222222-2222-2222-2222-222222222222/v2.0", "22222222-2222-2222-2222-222222222222", OrganizationsAuthority, false)]
    [InlineData("https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0", "not-a-guid", OrganizationsAuthority, false)]
    public void The_issuer_must_name_the_tokens_directory(string issuer, string tid, string authority, bool expected) =>
        Assert.Equal(expected, EntraSecurity.IssuerMatchesTenant(issuer, tid, authority));

    [Fact]
    public void The_issuer_must_sit_under_the_authority()
    {
        Assert.Equal("https://login.microsoftonline.com/x/v2.0", EntraSecurity.ValidateIssuerForAuthority("https://login.microsoftonline.com/x/v2.0", OrganizationsAuthority));
        Assert.Throws<SecurityTokenInvalidIssuerException>(() => EntraSecurity.ValidateIssuerForAuthority("https://sts.windows.net/x/", OrganizationsAuthority));
        Assert.Throws<SecurityTokenInvalidIssuerException>(() => EntraSecurity.ValidateIssuerForAuthority("http://login.microsoftonline.com/x/v2.0", OrganizationsAuthority));
        Assert.Throws<SecurityTokenInvalidIssuerException>(() => EntraSecurity.ValidateIssuerForAuthority("not a uri", OrganizationsAuthority));
    }

    [Theory]
    [InlineData(TenantAuthority, true)]
    [InlineData(OrganizationsAuthority, false)]
    [InlineData("https://login.microsoftonline.com/common/v2.0", false)]
    public void Single_tenant_authorities_are_recognised(string authority, bool expected) =>
        Assert.Equal(expected, EntraSecurity.IsSingleTenantAuthority(authority));

    [Fact]
    public void Failure_codes_never_carry_the_providers_message()
    {
        Assert.Equal("sso_denied", AuthenticationSetup.SsoFailureCode(new InvalidOperationException("Message contains error: 'access_denied', error_description: 'AADSTS...'")));
        Assert.Equal("sso_session_expired", AuthenticationSetup.SsoFailureCode(new InvalidOperationException("Correlation failed.")));
        Assert.Equal("sso_failed", AuthenticationSetup.SsoFailureCode(new InvalidOperationException("IDX10214: Audience validation failed")));
        Assert.Equal("sso_not_allowed", AuthenticationSetup.SsoFailureCode(new InvalidOperationException("x", new SsoRefusedException("sso_not_allowed", "y"))));
        Assert.Equal("sso_failed", AuthenticationSetup.SsoFailureCode(null));
    }

    [Fact]
    public void Roles_are_trimmed_bounded_and_unique()
    {
        var roles = SessionService.NormalizeRoles([" Admin ", "Admin", "", "bad\nrole", new string('r', 121), "Reader"]);
        Assert.Equal(new[] { "Admin", "Reader" }, roles);
    }
}

public sealed class StartupValidationTests
{
    private static IConfiguration Config(Dictionary<string, string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static Dictionary<string, string?> Secure()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new()
        {
            ["Authentication:Entra:Enabled"] = "true",
            ["Authentication:Entra:Authority"] = $"https://login.microsoftonline.com/{FakeEntra.TenantA}/v2.0",
            ["Authentication:Entra:ClientId"] = FakeEntra.ClientId,
            ["Authentication:Entra:ClientCredentialType"] = "ManagedIdentity",
            ["Jwt:SigningKey"] = key.ExportPkcs8PrivateKeyPem(),
            ["Database:Provider"] = "SqlServer",
            ["ConnectionStrings:Default"] = "Server=tcp:example.database.windows.net;Database=app;Authentication=Active Directory Default",
            ["Database:MigrateOnStartup"] = "false",
            ["DataProtection:KeyVaultKeyId"] = "https://example.vault.azure.net/keys/dataprotection"
        };
    }

    [Fact]
    public void A_secure_configuration_passes() => Assert.Empty(StartupValidation.Check(Config(Secure())));

    [Theory]
    [InlineData("Authentication:Entra:Enabled", "false", "Authentication:Entra must be enabled")]
    [InlineData("Authentication:Entra:Authority", "https://login.microsoftonline.com/organizations/v2.0", "AllowedTenantIds")]
    [InlineData("Authentication:Entra:AllowPersonalAccounts", "true", "AllowPersonalAccounts")]
    [InlineData("Jwt:SigningKey", "", "Jwt:SigningKey")]
    [InlineData("Database:Provider", "InMemory", "Database:Provider")]
    [InlineData("ConnectionStrings:Default", "", "ConnectionStrings:Default")]
    [InlineData("Database:MigrateOnStartup", "true", "MigrateOnStartup")]
    [InlineData("DataProtection:KeyVaultKeyId", "", "KeyVaultKeyId")]
    public void Each_insecure_setting_is_reported(string key, string value, string expected)
    {
        var settings = Secure();
        settings[key] = value;
        Assert.Contains(StartupValidation.Check(Config(settings)), e => e.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void A_multi_tenant_authority_with_an_allow_list_passes()
    {
        var settings = Secure();
        settings["Authentication:Entra:Authority"] = "https://login.microsoftonline.com/organizations/v2.0";
        settings["Authentication:Entra:AllowedTenantIds:0"] = FakeEntra.TenantA;
        Assert.Empty(StartupValidation.Check(Config(settings)));
    }

    [Fact]
    public void Production_refuses_to_start_with_an_insecure_configuration()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var f = new EntraFactory(new() { ["Jwt:SigningKey"] = key.ExportPkcs8PrivateKeyPem() }) { Environment = "Production" };
        var error = Assert.Throws<InvalidOperationException>(() => f.Services);
        Assert.Contains("Insecure production configuration", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Authentication:Entra:ClientCredentialType", "Password")]
    [InlineData("Authentication:Entra:ClientSecret", "")]
    [InlineData("Authentication:Entra:Authority", "https://login.microsoftonline.com/<directory-id>/v2.0")]
    [InlineData("Authentication:Entra:Authority", "http://login.microsoftonline.com/x/v2.0")]
    [InlineData("Authentication:Entra:MetadataAddress", "https://evil.example/.well-known/openid-configuration")]
    [InlineData("Authentication:Entra:CallbackPath", "/signin-oidc")]
    [InlineData("Authentication:Entra:AllowedTenantIds:0", "contoso.com")]
    public void A_broken_Entra_setting_stops_the_application(string key, string value)
    {
        using var f = new EntraFactory(new() { [key] = value });
        Assert.Throws<InvalidOperationException>(() => f.Services);
    }
}
