namespace AzureEntraStarter.Application.Authentication;

/// <summary>How this application proves its identity to Microsoft Entra when it redeems the authorization code.</summary>
public static class EntraClientCredentialTypes
{
    /// <summary>A client secret (simplest; must live in Key Vault or user-secrets and be rotated before it expires).</summary>
    public const string ClientSecret = "ClientSecret";
    /// <summary>A certificate (private_key_jwt): the private key never leaves this application.</summary>
    public const string Certificate = "Certificate";
    /// <summary>The App Service / Container Apps managed identity as a federated credential: no secret at all.</summary>
    public const string ManagedIdentity = "ManagedIdentity";

    public static bool IsValid(string? value) => value is ClientSecret or Certificate or ManagedIdentity;
}

/// <summary>Configuration section <c>Authentication:Entra</c>: sign-in with Microsoft Entra ID (OpenID Connect, code + PKCE).</summary>
public sealed class EntraOptions
{
    public const string Section = "Authentication:Entra";

    /// <summary>The Microsoft "consumers" directory: personal Microsoft accounts (Outlook.com, Hotmail, Xbox).</summary>
    public const string ConsumersTenantId = "9188040d-6c67-4c5b-b112-36a304b66dad";

    public bool Enabled { get; set; }
    /// <summary>For example <c>https://login.microsoftonline.com/{directory-id}/v2.0</c> (single tenant, recommended).</summary>
    public string Authority { get; set; } = string.Empty;
    /// <summary>Optional discovery document address; must use the same host as <see cref="Authority"/>.</summary>
    public string MetadataAddress { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientCredentialType { get; set; } = EntraClientCredentialTypes.ClientSecret;
    /// <summary>Secret. Only with <c>ClientCredentialType = ClientSecret</c>.</summary>
    public string ClientSecret { get; set; } = string.Empty;
    /// <summary>Secret. PKCS#12 (.pfx) as one line of base64, with the private key. Only with <c>Certificate</c>.</summary>
    public string ClientCertificate { get; set; } = string.Empty;
    public string ClientCertificatePassword { get; set; } = string.Empty;
    /// <summary>Client id of a user-assigned managed identity; empty uses the system-assigned identity.</summary>
    public string ManagedIdentityClientId { get; set; } = string.Empty;
    /// <summary>Audience of the managed identity token used as federated credential (public cloud default).</summary>
    public string ManagedIdentityAudience { get; set; } = "api://AzureADTokenExchange";
    /// <summary>Must stay under <c>/api/</c> so the Angular dev-server proxy forwards it.</summary>
    public string CallbackPath { get; set; } = "/api/auth/oidc/callback";
    /// <summary>Directory (tenant) ids allowed to sign in. Required in Production when the authority is multi-tenant.</summary>
    public string[] AllowedTenantIds { get; set; } = [];
    /// <summary>Personal Microsoft accounts are refused unless this is true (and the authority accepts them).</summary>
    public bool AllowPersonalAccounts { get; set; }
    /// <summary>Creates the local user on its first sign-in. When false, only users already in the database sign in.</summary>
    public bool AutoProvisionUsers { get; set; } = true;
    /// <summary>Sign-out also ends the Microsoft session (front-channel logout to Entra).</summary>
    public bool SignOutOfMicrosoft { get; set; }

    public bool IsConfigured => Enabled && !string.IsNullOrWhiteSpace(Authority) && !string.IsNullOrWhiteSpace(ClientId) && ClientCredentialType switch
    {
        EntraClientCredentialTypes.ClientSecret => !string.IsNullOrWhiteSpace(ClientSecret),
        EntraClientCredentialTypes.Certificate => !string.IsNullOrWhiteSpace(ClientCertificate),
        EntraClientCredentialTypes.ManagedIdentity => true,
        _ => false
    };
}

/// <summary>Configuration section <c>Jwt</c>: the application's own access tokens (ES256), kept in memory by the browser.</summary>
public sealed class JwtOptions
{
    public const string Section = "Jwt";

    public string Issuer { get; set; } = "AzureEntraStarter";
    public string Audience { get; set; } = "AzureEntraStarter.Api";
    /// <summary>Secret. P-256 private key, PEM or one line of base64 PKCS#8. Development generates a temporary one when empty.</summary>
    public string SigningKey { get; set; } = string.Empty;
    /// <summary>Public keys of earlier signing keys still accepted during a rotation (PEM or base64 SubjectPublicKeyInfo).</summary>
    public string[] PreviousPublicKeys { get; set; } = [];
    public int AccessTokenMinutes { get; set; } = 10;
}

/// <summary>Configuration section <c>Session</c>: the HttpOnly refresh cookie that keeps the browser signed in.</summary>
public sealed class SessionOptions
{
    public const string Section = "Session";

    /// <summary>Idle limit: a refresh credential not used for this long expires.</summary>
    public int RefreshTokenMinutes { get; set; } = 60;
    /// <summary>Absolute limit: after this the user signs in with Microsoft again, whatever the activity.</summary>
    public int MaxSessionHours { get; set; } = 12;
    /// <summary>A just-rotated refresh credential presented again within this window (another tab) is ignored, not treated as theft.</summary>
    public int ReuseGraceSeconds { get; set; } = 30;
    /// <summary>Lifetime of the one-time ticket that hands the Microsoft sign-in to the browser.</summary>
    public int SignInTicketSeconds { get; set; } = 120;
}
