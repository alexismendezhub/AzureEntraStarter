using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using AzureEntraStarter.Infrastructure.Authentication;
using AzureEntraStarter.Server.Authentication;
using AzureEntraStarter.Server.IntegrationTests.Support;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Server.IntegrationTests;

/// <summary>Deny by default, app roles from Entra, and access tokens that cannot be forged or reused outside their session.</summary>
public sealed class AuthorizationTests
{
    [Theory]
    [InlineData("/api/sample/hello")]
    [InlineData("/api/auth/me")]
    [InlineData("/api/admin/users")]
    [InlineData("/api/anything-else")]
    public async Task The_API_requires_a_session_by_default(string path)
    {
        using var f = new EntraFactory();
        var response = await f.NewBrowser().GetAsync(path);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/auth/config")]
    [InlineData("/.well-known/jwks.json")]
    [InlineData("/health/ready")]
    public async Task Only_the_public_endpoints_answer_without_a_session(string path)
    {
        using var f = new EntraFactory();
        Assert.Equal(HttpStatusCode.OK, (await f.NewBrowser().GetAsync(path)).StatusCode);
    }

    [Fact]
    public async Task A_signed_in_user_reaches_the_API()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var hello = await browser.GetAsync("/api/sample/hello");
        Assert.Equal(HttpStatusCode.OK, hello.StatusCode);
        Assert.Contains("Pat Doe", await hello.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/api/anything-else")).StatusCode);
    }

    [Fact]
    public async Task Administration_requires_the_Admin_app_role()
    {
        using var f = new EntraFactory();
        var member = f.NewBrowser();
        await member.SignInAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/api/admin/users")).StatusCode);

        f.Entra.Oid = "55555555-5555-5555-5555-555555555555";
        f.Entra.Roles.Add(AppRoles.Admin);
        var admin = f.NewBrowser();
        await admin.SignInAsync();
        var users = await (await admin.GetAsync("/api/admin/users")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, users.GetArrayLength());
    }

    [Fact]
    public async Task An_admin_can_disable_a_user_but_not_itself()
    {
        using var f = new EntraFactory();
        var member = f.NewBrowser();
        var memberBody = await member.SignInAsync();
        var memberId = memberBody.GetProperty("user").GetProperty("id").GetString();

        f.Entra.Oid = "55555555-5555-5555-5555-555555555555";
        f.Entra.Roles.Add(AppRoles.Admin);
        var admin = f.NewBrowser();
        var adminId = (await admin.SignInAsync()).GetProperty("user").GetProperty("id").GetString();

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/admin/users/{adminId}/disabled", new { disabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/admin/users/{memberId}/disabled", new { disabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await member.GetAsync("/api/sample/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/api/admin/users/{Guid.NewGuid()}/disabled", new { disabled = true })).StatusCode);
    }

    [Fact]
    public async Task Roles_are_those_of_the_sign_in_and_survive_refresh()
    {
        using var f = new EntraFactory();
        f.Entra.Roles.Add(AppRoles.Admin);
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        f.Entra.Roles.Clear();
        Assert.Equal(HttpStatusCode.OK, (await browser.RefreshAsync()).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task A_token_signed_with_another_key_is_refused()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var claims = new JsonWebTokenHandler().ReadJsonWebToken(browser.AccessToken!);
        var otherKey = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = claims.Kid };
        browser.AccessToken = Forge(claims, new SigningCredentials(otherKey, SecurityAlgorithms.EcdsaSha256));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task A_symmetric_or_unsigned_token_is_refused()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var claims = new JsonWebTokenHandler().ReadJsonWebToken(browser.AccessToken!);

        browser.AccessToken = Forge(claims, new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), SecurityAlgorithms.HmacSha256));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);

        var header = Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        var payload = browser.AccessToken.Split('.')[1];
        browser.AccessToken = $"{header}.{payload}.";
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task A_genuine_token_with_another_users_id_is_refused()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var keys = f.Services.GetRequiredService<TokenSigningKeys>();
        var claims = new JsonWebTokenHandler().ReadJsonWebToken(browser.AccessToken!);
        // Even signed by the application's own key, the sid must belong to the sub.
        browser.AccessToken = Forge(claims, keys.SigningCredentials, sub: Guid.NewGuid().ToString("D"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task The_access_token_is_never_accepted_from_a_cookie_or_the_query_string()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var token = browser.AccessToken!;
        browser.AccessToken = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me?access_token=" + token)).StatusCode);
        browser.Cookies.Add(new Uri(EntraFactory.Origin), new Cookie("access_token", token));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task The_published_keys_verify_the_access_tokens()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var jwks = new JsonWebKeySet(await (await browser.GetAsync("/.well-known/jwks.json")).Content.ReadAsStringAsync());
        var key = Assert.Single(jwks.Keys);
        Assert.Equal("EC", key.Kty);
        Assert.Equal("ES256", key.Alg);
        Assert.Null(key.D);
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(browser.AccessToken, new TokenValidationParameters
        {
            ValidIssuer = "AzureEntraStarter",
            ValidAudience = "AzureEntraStarter.Api",
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256]
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal(10, (int)Math.Round((((JsonWebToken)result.SecurityToken).ValidTo - ((JsonWebToken)result.SecurityToken).ValidFrom).TotalMinutes));
    }

    [Fact]
    public async Task The_spa_is_served_without_a_session_but_unknown_api_routes_are_not()
    {
        using var f = new EntraFactory();
        // wwwroot does not exist in tests, so the SPA fallback answers 404 rather than 401: it is anonymous.
        var page = await f.NewBrowser().GetAsync("/profile");
        Assert.NotEqual(HttpStatusCode.Unauthorized, page.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.NewBrowser().GetAsync("/api/profile")).StatusCode);
    }

    [Fact]
    public async Task Responses_carry_the_headers_that_protect_the_in_memory_token()
    {
        using var f = new EntraFactory();
        var response = await f.NewBrowser().GetAsync("/api/auth/config");
        var csp = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("script-src 'self';", csp, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("object-src 'none'", csp, StringComparison.Ordinal);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
    }

    private static string Forge(JsonWebToken original, SigningCredentials credentials, string? sub = null)
    {
        var claims = original.Claims.Where(c => c.Type is not ("aud" or "iss" or "exp" or "nbf" or "iat")).ToList();
        if (sub is not null)
        {
            claims.RemoveAll(c => c.Type == "sub");
            claims.Add(new Claim("sub", sub));
        }
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = original.Issuer,
            Audience = original.Audiences.Single(),
            Subject = new ClaimsIdentity(claims),
            Expires = original.ValidTo,
            NotBefore = original.ValidFrom,
            SigningCredentials = credentials
        });
    }
}
