using AzureEntraStarter.Application.Authentication;
using AzureEntraStarter.Infrastructure.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using static AzureEntraStarter.Server.Authentication.EntraSecurity;

using SessionOptions = AzureEntraStarter.Application.Authentication.SessionOptions;
namespace AzureEntraStarter.Server.Authentication;

internal static class AuthenticationSchemes
{
    /// <summary>The short-lived cookie that holds Microsoft's answer between its callback and the completion step.</summary>
    public const string External = "Entra.External";
    public const string Entra = "MicrosoftEntra";
}

/// <summary>Keys of the state carried (protected by the OpenID Connect handler) through the Microsoft round trip.</summary>
internal static class SsoProperties
{
    public const string ReturnUrl = "aesReturnUrl";
    public const string Prompt = "aesPrompt";
}

/// <summary>A sign-in Microsoft completed but this application refuses; <see cref="Code"/> goes to the browser.</summary>
public sealed class SsoRefusedException(string code, string message) : SecurityTokenValidationException(message)
{
    public string Code { get; } = code;
}

/// <summary>Coarse reasons sent back to /login (never the provider's or the handler's message).</summary>
public static class SsoErrorCodes
{
    public const string Denied = "sso_denied";
    public const string SessionExpired = "sso_session_expired";
    public const string Failed = "sso_failed";
    public const string NotAllowed = "sso_not_allowed";
    public const string PersonalAccount = "sso_personal_account";
    public const string NotRegistered = "sso_not_registered";
}

public static class AppRoles
{
    /// <summary>Value of the Entra app role that opens the administration endpoints.</summary>
    public const string Admin = "Admin";
}

internal static class AuthenticationSetup
{
    public static IServiceCollection AddEntraAuthentication(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.Configure<EntraOptions>(configuration.GetSection(EntraOptions.Section));
        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.Section));
        services.Configure<SessionOptions>(configuration.GetSection(SessionOptions.Section));
        services.AddSingleton(TimeProvider.System);

        var jwt = configuration.GetSection(JwtOptions.Section).Get<JwtOptions>() ?? new JwtOptions();
        var signingKeys = TokenSigningKeys.FromOptions(jwt, allowEphemeral: environment.IsDevelopment() || environment.IsEnvironment("Testing"));
        services.AddSingleton(signingKeys);
        services.AddScoped<SessionService>();

        var entra = configuration.GetSection(EntraOptions.Section).Get<EntraOptions>() ?? new EntraOptions();
        if (!EntraClientCredentialTypes.IsValid(entra.ClientCredentialType))
            throw new InvalidOperationException("Authentication:Entra:ClientCredentialType must be ClientSecret, Certificate or ManagedIdentity.");
        if (entra.Enabled && !entra.IsConfigured)
            throw new InvalidOperationException("Authentication:Entra is enabled but Authority, ClientId or the client credential is missing.");
        var allowedTenants = entra.AllowedTenantIds.Where(x => !string.IsNullOrWhiteSpace(x)).Select(CanonicalGuid).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Uri? metadataAddress = null;
        var callbackPath = entra.CallbackPath;
        if (entra.IsConfigured)
        {
            if (entra.Authority.Contains('<', StringComparison.Ordinal))
                throw new InvalidOperationException("Authentication:Entra:Authority still contains the <directory-id> placeholder.");
            var authority = RequireHttpsUri(entra.Authority, "Authentication:Entra:Authority");
            if (!string.IsNullOrWhiteSpace(entra.MetadataAddress))
            {
                metadataAddress = RequireHttpsUri(entra.MetadataAddress, "Authentication:Entra:MetadataAddress");
                RequireSameAuthorityHost(metadataAddress, authority, "Authentication:Entra:MetadataAddress");
            }
            callbackPath = RequireCallbackPath(entra.CallbackPath);
            switch (entra.ClientCredentialType)
            {
                case EntraClientCredentialTypes.Certificate:
                    services.AddSingleton<IClientAssertionProvider>(sp => new CertificateClientAssertionProvider(entra, sp.GetRequiredService<TimeProvider>()));
                    break;
                case EntraClientCredentialTypes.ManagedIdentity:
                    services.AddSingleton<IClientAssertionProvider>(_ => ManagedIdentityClientAssertionProvider.FromOptions(entra));
                    break;
            }
        }

        // The access token travels only in the Authorization header; it is never read from a cookie or the query string.
        var auth = services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
        {
            o.MapInboundClaims = false;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwt.Issuer,
                ValidateAudience = true,
                ValidAudience = jwt.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys.ValidationKeys,
                // Only ES256: a token cannot pick a weaker algorithm (or "none") for itself.
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1),
                NameClaimType = "name",
                RoleClaimType = "role"
            };
        });

        if (entra.IsConfigured)
        {
            auth.AddCookie(AuthenticationSchemes.External, o =>
            {
                o.Cookie.Name = AuthCookies.ExternalCookieName;
                o.Cookie.HttpOnly = true;
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.Cookie.Path = "/";
                o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                o.SlidingExpiration = false;
            });

            auth.AddOpenIdConnect(AuthenticationSchemes.Entra, o =>
            {
                o.SignInScheme = AuthenticationSchemes.External;
                o.Authority = entra.Authority.Trim().TrimEnd('/');
                if (metadataAddress is not null) o.MetadataAddress = metadataAddress.AbsoluteUri;
                o.RequireHttpsMetadata = true;
                o.ClientId = entra.ClientId;
                // Certificate / managed identity: no secret is configured; the assertion is added per request below.
                o.ClientSecret = entra.ClientCredentialType == EntraClientCredentialTypes.ClientSecret ? entra.ClientSecret : null;
                o.ResponseType = OpenIdConnectResponseType.Code;
                o.UsePkce = true;
                o.CallbackPath = callbackPath;
                o.SaveTokens = false;
                o.GetClaimsFromUserInfoEndpoint = false;
                o.MapInboundClaims = false;
                // The handler owns correlation/state and nonce validation. Its temporary cookies are explicit, host-only and
                // Secure; SameSite=None because Microsoft answers with a cross-site form POST.
                o.CorrelationCookie.HttpOnly = true;
                o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
                o.CorrelationCookie.SameSite = SameSiteMode.None;
                o.NonceCookie.HttpOnly = true;
                o.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
                o.NonceCookie.SameSite = SameSiteMode.None;
                o.Scope.Clear();
                o.Scope.Add("openid");
                o.Scope.Add("profile");
                o.Scope.Add("email");
                o.TokenValidationParameters.ValidateIssuer = true;
                o.TokenValidationParameters.IssuerValidator = (issuer, _, _) => ValidateIssuerForAuthority(issuer, entra.Authority);
                o.TokenValidationParameters.ValidateAudience = true;
                o.TokenValidationParameters.ValidAudience = entra.ClientId;
                o.TokenValidationParameters.ValidateLifetime = true;
                o.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(1);
                o.TokenValidationParameters.NameClaimType = "name";
                o.TokenValidationParameters.RoleClaimType = "roles";
                o.Events = new OpenIdConnectEvents
                {
                    // A failed or cancelled round trip returns to sign-in with a coarse reason, never a 500 or the provider's message.
                    OnRemoteFailure = context =>
                    {
                        var code = SsoFailureCode(context.Failure);
                        context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("AzureEntraStarter.Sso")
                            .LogWarning("Microsoft Entra sign-in failed: {SsoFailure}", code);
                        context.Response.Redirect("/login?ssoError=" + code);
                        context.HandleResponse();
                        return Task.CompletedTask;
                    },
                    OnRedirectToIdentityProvider = context =>
                    {
                        if (context.Properties.Items.TryGetValue(SsoProperties.Prompt, out var prompt) && prompt is "login" or "select_account")
                            context.ProtocolMessage.Prompt = prompt;
                        return Task.CompletedTask;
                    },
                    OnAuthorizationCodeReceived = async context =>
                    {
                        var assertions = context.HttpContext.RequestServices.GetService<IClientAssertionProvider>();
                        if (assertions is null || context.TokenEndpointRequest is null) return;
                        var configuration = await context.Options.ConfigurationManager!.GetConfigurationAsync(context.HttpContext.RequestAborted);
                        context.TokenEndpointRequest.ClientSecret = null;
                        context.TokenEndpointRequest.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                        context.TokenEndpointRequest.ClientAssertion = await assertions.GetAssertionAsync(configuration.TokenEndpoint, context.HttpContext.RequestAborted);
                    },
                    OnTokenValidated = context =>
                    {
                        var tid = context.Principal?.FindFirst("tid")?.Value ?? string.Empty;
                        var oid = context.Principal?.FindFirst("oid")?.Value ?? string.Empty;
                        var issuer = context.SecurityToken?.Issuer ?? context.Principal?.FindFirst("iss")?.Value ?? string.Empty;
                        if (!Guid.TryParse(tid, out var tidGuid) || !Guid.TryParse(oid, out _))
                            throw new SecurityTokenValidationException("Microsoft Entra tokens must contain immutable GUID tid and oid claims.");
                        if (!IssuerMatchesTenant(issuer, tid, entra.Authority))
                            throw new SecurityTokenInvalidIssuerException("The token issuer does not correspond to its directory id under the configured authority.");
                        var canonicalTid = tidGuid.ToString("D");
                        if (!entra.AllowPersonalAccounts && string.Equals(canonicalTid, EntraOptions.ConsumersTenantId, StringComparison.OrdinalIgnoreCase))
                            throw new SsoRefusedException(SsoErrorCodes.PersonalAccount, "Personal Microsoft accounts are not allowed.");
                        if (allowedTenants.Count > 0 && !allowedTenants.Contains(canonicalTid))
                            throw new SsoRefusedException(SsoErrorCodes.NotAllowed, "The Microsoft Entra directory is not allowed by configuration.");
                        return Task.CompletedTask;
                    }
                };
            });
        }

        // Deny by default: an endpoint without an explicit rule requires a signed-in user with a live session.
        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy(AppRoles.Admin, p => p.RequireAuthenticatedUser().RequireRole(AppRoles.Admin));
        return services;
    }

    internal static string SsoFailureCode(Exception? failure)
    {
        for (var e = failure; e is not null; e = e.InnerException)
            if (e is SsoRefusedException refused) return refused.Code;
        var message = failure?.Message ?? string.Empty;
        return message.Contains("access_denied", StringComparison.Ordinal) ? SsoErrorCodes.Denied
            : message.Contains("Correlation failed", StringComparison.Ordinal) ? SsoErrorCodes.SessionExpired
            : SsoErrorCodes.Failed;
    }
}
