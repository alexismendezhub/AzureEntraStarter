using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using AzureEntraStarter.Application.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Infrastructure.Authentication;

/// <summary>Signs a short-lived assertion with the application's certificate (RS256 + x5t, as Microsoft Entra expects).</summary>
public sealed class CertificateClientAssertionProvider : IClientAssertionProvider, IDisposable
{
    private readonly string _clientId;
    private readonly X509Certificate2 _certificate;
    private readonly SigningCredentials _credentials;
    private readonly TimeProvider _time;

    public CertificateClientAssertionProvider(EntraOptions options, TimeProvider time)
    {
        _clientId = options.ClientId;
        _time = time;
        try
        {
            _certificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(options.ClientCertificate.Trim()),
                string.IsNullOrEmpty(options.ClientCertificatePassword) ? null : options.ClientCertificatePassword,
                X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            throw new InvalidOperationException("Authentication:Entra:ClientCertificate is not a readable PKCS#12 (.pfx) in base64.", ex);
        }
        var rsa = _certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Authentication:Entra:ClientCertificate must be an RSA certificate with its private key.");
        if (rsa.KeySize < 2048) throw new InvalidOperationException("Authentication:Entra:ClientCertificate must use an RSA key of 2048 bits or more.");
        // X509SigningCredentials puts the certificate's base64url SHA-1 thumbprint in the x5t header, which Microsoft Entra
        // uses to find the certificate uploaded to the app registration.
        _credentials = new X509SigningCredentials(_certificate, SecurityAlgorithms.RsaSha256);
    }

    public Task<string> GetAssertionAsync(string tokenEndpoint, CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _clientId,
            Audience = tokenEndpoint,
            Subject = new System.Security.Claims.ClaimsIdentity([new System.Security.Claims.Claim("sub", _clientId), new System.Security.Claims.Claim("jti", Guid.NewGuid().ToString("N"))]),
            NotBefore = now.AddSeconds(-30),
            IssuedAt = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = _credentials
        });
        return Task.FromResult(token);
    }

    public void Dispose() => _certificate.Dispose();
}

/// <summary>
/// A managed identity token (audience <c>api://AzureADTokenExchange</c>) used as the client assertion: the app
/// registration trusts this identity through a federated identity credential, so no secret or certificate exists.
/// </summary>
public sealed class ManagedIdentityClientAssertionProvider(TokenCredential credential, string audience) : IClientAssertionProvider
{
    public static ManagedIdentityClientAssertionProvider FromOptions(EntraOptions options) => new(
        string.IsNullOrWhiteSpace(options.ManagedIdentityClientId)
            ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
            : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(options.ManagedIdentityClientId.Trim())),
        options.ManagedIdentityAudience);

    public async Task<string> GetAssertionAsync(string tokenEndpoint, CancellationToken cancellationToken)
    {
        var token = await credential.GetTokenAsync(new TokenRequestContext([audience.TrimEnd('/') + "/.default"]), cancellationToken).ConfigureAwait(false);
        return token.Token;
    }
}
