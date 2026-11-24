using System.Security.Cryptography;
using AzureEntraStarter.Application.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Infrastructure.Authentication;

/// <summary>
/// The keys that sign and verify the application's access tokens (ES256). A private P-256 key signs; the public keys
/// (current and earlier ones still in rotation) are published at <c>/.well-known/jwks.json</c> so other services can
/// verify the tokens without holding any secret.
/// </summary>
public sealed class TokenSigningKeys
{
    public SigningCredentials SigningCredentials { get; }
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }
    public IReadOnlyList<JsonWebKey> PublicKeys { get; }
    /// <summary>True when the key was generated at startup (Development only): tokens die with the process.</summary>
    public bool IsEphemeral { get; }

    private TokenSigningKeys(SigningCredentials signing, IReadOnlyList<SecurityKey> validation, IReadOnlyList<JsonWebKey> publicKeys, bool ephemeral)
    {
        SigningCredentials = signing;
        ValidationKeys = validation;
        PublicKeys = publicKeys;
        IsEphemeral = ephemeral;
    }

    public static TokenSigningKeys FromOptions(JwtOptions jwt, bool allowEphemeral)
    {
        var ephemeral = false;
        var current = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (string.IsNullOrWhiteSpace(jwt.SigningKey))
        {
            if (!allowEphemeral)
                throw new InvalidOperationException("Jwt:SigningKey is required. Generate a P-256 key (see README) and keep it in Key Vault or user-secrets.");
            ephemeral = true;
        }
        else
        {
            ImportKey(current, jwt.SigningKey, privateKey: true, "Jwt:SigningKey");
        }

        var signingKey = PublicKeyOf(current);
        var signingWithPrivate = new ECDsaSecurityKey(current) { KeyId = signingKey.KeyId };
        var validation = new List<SecurityKey> { signingKey };
        var published = new List<JsonWebKey> { ToJwk(signingKey) };
        foreach (var previous in jwt.PreviousPublicKeys.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            var key = ECDsa.Create();
            ImportKey(key, previous, privateKey: false, "Jwt:PreviousPublicKeys");
            var publicKey = PublicKeyOf(key);
            if (validation.Any(x => x.KeyId == publicKey.KeyId)) continue;
            validation.Add(publicKey);
            published.Add(ToJwk(publicKey));
        }
        return new TokenSigningKeys(new SigningCredentials(signingWithPrivate, SecurityAlgorithms.EcdsaSha256), validation, published, ephemeral);
    }

    // PEM ("-----BEGIN ...") or one line of base64: PKCS#8 for the private key, SubjectPublicKeyInfo for a public key.
    private static void ImportKey(ECDsa key, string value, bool privateKey, string setting)
    {
        try
        {
            var text = value.Trim();
            if (text.StartsWith("-----BEGIN", StringComparison.Ordinal)) key.ImportFromPem(text);
            else if (privateKey) key.ImportPkcs8PrivateKey(Convert.FromBase64String(text), out _);
            else key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(text), out _);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            throw new InvalidOperationException($"{setting} is not a readable {(privateKey ? "private" : "public")} key.", ex);
        }
        if (key.KeySize != 256) throw new InvalidOperationException($"{setting} must be a P-256 (ES256) key.");
        if (privateKey)
        {
            try { key.ExportParameters(true); }
            catch (CryptographicException ex) { throw new InvalidOperationException($"{setting} must contain the private key.", ex); }
        }
    }

    // The key id is derived from the public key, so it never has to be configured and changes with every new key.
    private static ECDsaSecurityKey PublicKeyOf(ECDsa key)
    {
        var spki = key.ExportSubjectPublicKeyInfo();
        var publicOnly = ECDsa.Create();
        publicOnly.ImportSubjectPublicKeyInfo(spki, out _);
        return new ECDsaSecurityKey(publicOnly) { KeyId = Base64UrlEncoder.Encode(SHA256.HashData(spki))[..16] };
    }

    private static JsonWebKey ToJwk(ECDsaSecurityKey key)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.EcdsaSha256;
        return jwk;
    }
}
