using System.Security.Cryptography;
using AzureEntraStarter.Server.IntegrationTests.Support;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AzureEntraStarter.Server.IntegrationTests;

/// <summary>Everything Microsoft's answer must satisfy; a refusal returns to /login with a coarse reason and creates nothing.</summary>
public sealed class TokenValidationTests
{
    private const string Common = "https://login.microsoftonline.com/common/v2.0";
    private const string Organizations = "https://login.microsoftonline.com/organizations/v2.0";

    private static async Task AssertRefused(EntraFactory f, string code, Action<IDictionary<string, string>>? alterCallback = null)
    {
        var landing = await f.NewBrowser().RoundTripAsync(alterCallback: alterCallback);
        Assert.Equal("/login?ssoError=" + code, landing.OriginalString);
        Assert.Equal(0, await f.WithDbAsync(db => db.Users.CountAsync()));
        Assert.Equal(0, await f.WithDbAsync(db => db.SignInTickets.CountAsync()));
    }

    [Fact]
    public async Task A_token_of_another_directory_is_refused_by_a_single_tenant_authority()
    {
        using var f = new EntraFactory();
        f.Entra.Tid = FakeEntra.TenantB;
        await AssertRefused(f, "sso_failed");
    }

    [Fact]
    public async Task A_directory_outside_the_allow_list_is_refused()
    {
        using var f = new EntraFactory(new()
        {
            ["Authentication:Entra:Authority"] = Organizations,
            ["Authentication:Entra:AllowedTenantIds:0"] = FakeEntra.TenantA
        });
        f.Entra.Tid = FakeEntra.TenantB;
        await AssertRefused(f, "sso_not_allowed");

        f.Entra.Tid = FakeEntra.TenantA;
        await f.NewBrowser().SignInAsync();
    }

    [Fact]
    public async Task Personal_Microsoft_accounts_are_refused_unless_allowed()
    {
        using var refused = new EntraFactory(new() { ["Authentication:Entra:Authority"] = Common });
        refused.Entra.Tid = "9188040d-6c67-4c5b-b112-36a304b66dad";
        await AssertRefused(refused, "sso_personal_account");

        using var allowed = new EntraFactory(new()
        {
            ["Authentication:Entra:Authority"] = Common,
            ["Authentication:Entra:AllowPersonalAccounts"] = "true"
        });
        allowed.Entra.Tid = "9188040d-6c67-4c5b-b112-36a304b66dad";
        await allowed.NewBrowser().SignInAsync();
    }

    [Fact]
    public async Task An_issuer_that_does_not_name_the_tokens_directory_is_refused()
    {
        // Multi-tenant authority: the token says tid = B but its issuer is A's.
        using var f = new EntraFactory(new() { ["Authentication:Entra:Authority"] = Organizations });
        f.Entra.Tid = FakeEntra.TenantB;
        f.Entra.Issuer = FakeEntra.IssuerFor(FakeEntra.TenantA);
        await AssertRefused(f, "sso_failed");
    }

    [Theory]
    [InlineData("https://evil.example/11111111-1111-1111-1111-111111111111/v2.0")]
    [InlineData("https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/")]
    [InlineData("https://sts.windows.net/11111111-1111-1111-1111-111111111111/")]
    [InlineData("http://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0")]
    public async Task An_issuer_outside_the_configured_authority_is_refused(string issuer)
    {
        using var f = new EntraFactory();
        f.Entra.Issuer = issuer;
        await AssertRefused(f, "sso_failed");
    }

    [Fact]
    public async Task A_token_without_an_object_id_is_refused()
    {
        using var f = new EntraFactory();
        f.Entra.Oid = null;
        await AssertRefused(f, "sso_failed");
    }

    [Fact]
    public async Task A_token_for_another_application_is_refused()
    {
        using var f = new EntraFactory();
        f.Entra.Audience = "bbbbbbbb-0000-0000-0000-000000000002";
        await AssertRefused(f, "sso_failed");
    }

    [Fact]
    public async Task An_expired_token_is_refused()
    {
        using var f = new EntraFactory();
        f.Entra.Lifetime = TimeSpan.FromMinutes(-10);
        await AssertRefused(f, "sso_failed");
    }

    [Fact]
    public async Task A_token_signed_by_another_key_is_refused()
    {
        using var f = new EntraFactory();
        f.Entra.SignWith = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "entra-key" };
        await AssertRefused(f, "sso_failed");
    }

    [Fact]
    public async Task A_replayed_nonce_is_refused()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        var start = await browser.GetAsync("/api/auth/entra/start");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(start.Headers.Location!.Query)["state"].ToString();
        f.Entra.Nonce = "a-nonce-this-browser-never-got";
        var callback = await browser.Http.PostAsync("/api/auth/oidc/callback", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = "good-code", ["state"] = state }));
        Assert.Equal("/login?ssoError=sso_failed", callback.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task A_cancelled_sign_in_reports_denied()
    {
        using var f = new EntraFactory();
        await AssertRefused(f, "sso_denied", form =>
        {
            form.Remove("code");
            form["error"] = "access_denied";
            form["error_description"] = "AADSTS65004: User declined to consent.";
        });
    }

    [Fact]
    public async Task A_bad_code_fails_without_details()
    {
        using var f = new EntraFactory();
        await AssertRefused(f, "sso_failed", form => form["code"] = "stolen-or-old-code");
    }

    [Fact]
    public async Task A_callback_from_another_browser_fails_the_correlation_check()
    {
        using var f = new EntraFactory();
        var start = await f.NewBrowser().GetAsync("/api/auth/entra/start");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(start.Headers.Location!.Query)["state"].ToString();
        // The attacker's browser never received the correlation cookie.
        var callback = await f.NewBrowser().Http.PostAsync("/api/auth/oidc/callback", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = "good-code", ["state"] = state }));
        Assert.Equal("/login?ssoError=sso_session_expired", callback.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Roles_from_Microsoft_are_bounded()
    {
        using var f = new EntraFactory();
        f.Entra.Roles.AddRange(Enumerable.Range(0, 80).Select(i => "Role" + i));
        f.Entra.Roles.Add(new string('x', 500));
        f.Entra.Roles.Add("Role1");
        var body = await f.NewBrowser().SignInAsync();
        var roles = body.GetProperty("user").GetProperty("roles").EnumerateArray().Select(r => r.GetString()).ToList();
        Assert.Equal(50, roles.Count);
        Assert.DoesNotContain(roles, r => r!.Length > 120);
        Assert.Equal(roles.Count, roles.Distinct().Count());
    }
}
