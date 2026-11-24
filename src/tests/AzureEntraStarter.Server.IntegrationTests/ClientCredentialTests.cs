using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using AzureEntraStarter.Application.Authentication;
using AzureEntraStarter.Infrastructure.Authentication;
using AzureEntraStarter.Server.IntegrationTests.Support;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Server.IntegrationTests;

/// <summary>How the application proves itself when it redeems the code: secret, certificate, or managed identity.</summary>
public sealed class ClientCredentialTests
{
    [Fact]
    public async Task With_a_client_secret_the_secret_is_sent_only_to_the_token_endpoint()
    {
        using var f = new EntraFactory();
        await f.NewBrowser().SignInAsync();
        Assert.Equal(FakeEntra.ClientSecret, f.Entra.LastTokenRequest!["client_secret"].ToString());
        Assert.False(f.Entra.LastTokenRequest.ContainsKey("client_assertion"));
    }

    [Fact]
    public async Task With_a_certificate_a_signed_assertion_replaces_the_secret()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=AzureEntraStarter test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var f = new EntraFactory(new()
        {
            ["Authentication:Entra:ClientCredentialType"] = "Certificate",
            ["Authentication:Entra:ClientSecret"] = "",
            ["Authentication:Entra:ClientCertificate"] = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx, "pfx-password")),
            ["Authentication:Entra:ClientCertificatePassword"] = "pfx-password"
        });
        string? problem = "not called";
        f.Entra.ClientAuthentication = form =>
        {
            if (form.ContainsKey("client_secret")) return problem = "a secret was sent";
            if (form["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") return problem = "assertion type";
            var result = new JsonWebTokenHandler().ValidateTokenAsync(form["client_assertion"].ToString(), new TokenValidationParameters
            {
                ValidIssuer = FakeEntra.ClientId,
                ValidAudience = FakeEntra.TokenEndpoint,
                IssuerSigningKey = new X509SecurityKey(certificate),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
            }).GetAwaiter().GetResult();
            if (!result.IsValid) return problem = "signature: " + result.Exception?.Message;
            var token = (JsonWebToken)result.SecurityToken;
            if (token.Subject != FakeEntra.ClientId || string.IsNullOrEmpty(token.Id)) return problem = "claims";
            if (token.ValidTo > DateTime.UtcNow.AddMinutes(6)) return problem = "lifetime";
            if (!token.TryGetHeaderValue<string>("x5t", out var x5t) || x5t != Base64UrlEncoder.Encode(certificate.GetCertHash())) return problem = "x5t";
            return problem = null;
        };

        var landing = await f.NewBrowser().RoundTripAsync();
        Assert.Null(problem);
        Assert.StartsWith("/login#ticket=", landing.OriginalString);
    }

    [Fact]
    public void A_certificate_without_its_private_key_is_refused_at_startup()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=public only", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        using var publicOnly = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
        var options = new EntraOptions
        {
            ClientId = FakeEntra.ClientId,
            ClientCertificate = Convert.ToBase64String(publicOnly.Export(X509ContentType.Pfx))
        };
        Assert.Throws<InvalidOperationException>(() => new CertificateClientAssertionProvider(options, TimeProvider.System));
        Assert.Throws<InvalidOperationException>(() => new CertificateClientAssertionProvider(new EntraOptions { ClientCertificate = "not base64!" }, TimeProvider.System));
    }

    private sealed class FakeManagedIdentity : TokenCredential
    {
        public string[]? Scopes { get; private set; }
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new NotSupportedException();
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Scopes = requestContext.Scopes;
            return ValueTask.FromResult(new AccessToken("managed-identity-token", DateTimeOffset.UtcNow.AddHours(1)));
        }
    }

    [Fact]
    public async Task With_a_managed_identity_its_token_is_the_assertion_and_no_secret_exists()
    {
        var identity = new FakeManagedIdentity();
        using var f = new EntraFactory(new()
        {
            ["Authentication:Entra:ClientCredentialType"] = "ManagedIdentity",
            ["Authentication:Entra:ClientSecret"] = ""
        })
        {
            // Azure's managed identity endpoint does not exist here: the credential is replaced, the provider is the real one.
            TestServices = services =>
            {
                services.RemoveAll<IClientAssertionProvider>();
                services.AddSingleton<IClientAssertionProvider>(new ManagedIdentityClientAssertionProvider(identity, "api://AzureADTokenExchange"));
            }
        };
        f.Entra.ClientAuthentication = form =>
            !form.ContainsKey("client_secret") && form["client_assertion"] == "managed-identity-token" &&
            form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ? null : "bad assertion";

        await f.NewBrowser().SignInAsync();
        Assert.Equal(new[] { "api://AzureADTokenExchange/.default" }, identity.Scopes);
    }

    [Fact]
    public void The_managed_identity_provider_is_registered_from_configuration()
    {
        using var f = new EntraFactory(new()
        {
            ["Authentication:Entra:ClientCredentialType"] = "ManagedIdentity",
            ["Authentication:Entra:ClientSecret"] = "",
            ["Authentication:Entra:ManagedIdentityClientId"] = "cccccccc-0000-0000-0000-000000000003"
        });
        Assert.IsType<ManagedIdentityClientAssertionProvider>(f.Services.GetRequiredService<IClientAssertionProvider>());
    }
}
