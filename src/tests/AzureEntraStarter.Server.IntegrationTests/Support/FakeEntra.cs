using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Server.IntegrationTests.Support;

/// <summary>
/// A stand-in for Microsoft Entra's token endpoint: it redeems "good-code" (PKCE required) and answers with an ID token
/// signed by its own key, built from the properties below. Discovery is replaced by a static configuration.
/// </summary>
public sealed class FakeEntra : HttpMessageHandler
{
    public const string TenantA = "11111111-1111-1111-1111-111111111111";
    public const string TenantB = "22222222-2222-2222-2222-222222222222";
    public const string ClientId = "aaaaaaaa-0000-0000-0000-000000000001";
    public const string ClientSecret = "test-client-secret";
    public const string Host = "https://login.microsoftonline.com";
    public const string AuthorizeEndpoint = Host + "/common/oauth2/v2.0/authorize";
    public const string TokenEndpoint = Host + "/common/oauth2/v2.0/token";
    public const string EndSessionEndpoint = Host + "/common/oauth2/v2.0/logout";

    public RsaSecurityKey SigningKey { get; } = new(RSA.Create(2048)) { KeyId = "entra-key" };

    // The next ID token.
    public string Tid { get; set; } = TenantA;
    public string? Oid { get; set; } = "33333333-3333-3333-3333-333333333333";
    /// <summary>Null: https://login.microsoftonline.com/{Tid}/v2.0, as Microsoft issues it.</summary>
    public string? Issuer { get; set; }
    public string Audience { get; set; } = ClientId;
    public string Name { get; set; } = "Pat Doe";
    public string? Email { get; set; } = "pat@contoso.example";
    public string PreferredUsername { get; set; } = "pat@contoso.example";
    public List<string> Roles { get; } = [];
    public string Nonce { get; set; } = string.Empty;
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(5);
    public SecurityKey? SignWith { get; set; }

    /// <summary>Checks the client authentication; returns null when it is acceptable.</summary>
    public Func<Dictionary<string, StringValues>, string?> ClientAuthentication { get; set; } = form =>
        form.TryGetValue("client_secret", out var s) && s == ClientSecret && !form.ContainsKey("client_assertion") ? null : "bad client secret";

    public Dictionary<string, StringValues>? LastTokenRequest { get; private set; }
    public string? LastError { get; private set; }

    public static string IssuerFor(string tid) => $"{Host}/{tid}/v2.0";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri?.AbsoluteUri != TokenEndpoint) return new HttpResponseMessage(HttpStatusCode.NotFound);
        var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
        LastTokenRequest = form;
        LastError = form["grant_type"] != "authorization_code" ? "grant_type"
            : form["code"] != "good-code" ? "code"
            : string.IsNullOrEmpty(form["code_verifier"]) ? "no PKCE"
            : form["client_id"] != ClientId ? "client_id"
            : ClientAuthentication(form);
        if (LastError is not null)
            return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = JsonContent.Create(new { error = "invalid_grant", error_description = LastError }) };

        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["tid"] = Tid,
            ["nonce"] = Nonce,
            ["name"] = Name,
            ["preferred_username"] = PreferredUsername,
            ["sub"] = "pairwise-subject",
            ["ver"] = "2.0"
        };
        if (Oid is not null) claims["oid"] = Oid;
        if (Email is not null) claims["email"] = Email;
        if (Roles.Count > 0) claims["roles"] = Roles.ToArray();
        var idToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer ?? IssuerFor(Tid),
            Audience = Audience,
            IssuedAt = now.Add(Lifetime < TimeSpan.Zero ? Lifetime : TimeSpan.Zero).AddMinutes(-1),
            NotBefore = now.Add(Lifetime < TimeSpan.Zero ? Lifetime : TimeSpan.Zero).AddMinutes(-1),
            Expires = now.Add(Lifetime),
            Claims = claims,
            SigningCredentials = new SigningCredentials(SignWith ?? SigningKey, SecurityAlgorithms.RsaSha256)
        });
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { id_token = idToken, access_token = "graph-access-token", token_type = "Bearer", expires_in = 300 })
        };
    }
}
