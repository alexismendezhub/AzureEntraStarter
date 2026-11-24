using System.Security.Cryptography;
using AzureEntraStarter.Application.Authentication;
using AzureEntraStarter.Infrastructure.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Infrastructure.UnitTests;

public sealed class TokenSigningKeysTests
{
    [Fact]
    public void A_PEM_or_base64_P256_key_signs_and_its_public_key_is_published()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fromPem = TokenSigningKeys.FromOptions(new JwtOptions { SigningKey = key.ExportPkcs8PrivateKeyPem() }, allowEphemeral: false);
        var fromBase64 = TokenSigningKeys.FromOptions(new JwtOptions { SigningKey = Convert.ToBase64String(key.ExportPkcs8PrivateKey()) }, allowEphemeral: false);
        Assert.Equal(fromPem.SigningCredentials.Key.KeyId, fromBase64.SigningCredentials.Key.KeyId);
        Assert.False(fromPem.IsEphemeral);
        var jwk = Assert.Single(fromPem.PublicKeys);
        Assert.Null(jwk.D);
        Assert.Equal(SecurityAlgorithms.EcdsaSha256, fromPem.SigningCredentials.Algorithm);
    }

    [Fact]
    public void Previous_public_keys_keep_validating_during_a_rotation()
    {
        using var current = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var previous = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = TokenSigningKeys.FromOptions(new JwtOptions
        {
            SigningKey = current.ExportPkcs8PrivateKeyPem(),
            PreviousPublicKeys = [previous.ExportSubjectPublicKeyInfoPem(), previous.ExportSubjectPublicKeyInfoPem()]
        }, allowEphemeral: false);
        Assert.Equal(2, keys.ValidationKeys.Count);
        Assert.Equal(2, keys.PublicKeys.Count);
    }

    [Fact]
    public void Bad_keys_stop_the_application()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<InvalidOperationException>(() => TokenSigningKeys.FromOptions(new JwtOptions(), allowEphemeral: false));
        Assert.Throws<InvalidOperationException>(() => TokenSigningKeys.FromOptions(new JwtOptions { SigningKey = "not a key" }, allowEphemeral: false));
        Assert.Throws<InvalidOperationException>(() => TokenSigningKeys.FromOptions(new JwtOptions { SigningKey = p384.ExportPkcs8PrivateKeyPem() }, allowEphemeral: false));
        Assert.Throws<InvalidOperationException>(() => TokenSigningKeys.FromOptions(new JwtOptions { SigningKey = p256.ExportSubjectPublicKeyInfoPem() }, allowEphemeral: false));
        Assert.True(TokenSigningKeys.FromOptions(new JwtOptions(), allowEphemeral: true).IsEphemeral);
    }
}
