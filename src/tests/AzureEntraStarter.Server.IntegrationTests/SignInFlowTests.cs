using System.Text.Json;
using AzureEntraStarter.Domain.Users;
using AzureEntraStarter.Server.IntegrationTests.Support;
using AzureEntraStarter.Server.Security;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace AzureEntraStarter.Server.IntegrationTests;

/// <summary>The Microsoft Entra round trip, end to end, against the stand-in token endpoint.</summary>
public sealed class SignInFlowTests
{
    [Fact]
    public async Task Start_redirects_to_Microsoft_with_code_flow_PKCE_state_and_nonce()
    {
        using var f = new EntraFactory();
        var start = await f.NewBrowser().GetAsync("/api/auth/entra/start");

        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var location = start.Headers.Location!;
        Assert.StartsWith(FakeEntra.AuthorizeEndpoint, location.AbsoluteUri);
        var q = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(FakeEntra.ClientId, q["client_id"].ToString());
        Assert.Equal("code", q["response_type"].ToString());
        Assert.Equal("form_post", q["response_mode"].ToString());
        Assert.Equal("S256", q["code_challenge_method"].ToString());
        Assert.True(q["code_challenge"].ToString().Length >= 43);
        Assert.Equal("openid profile email", q["scope"].ToString());
        Assert.Equal("https://localhost/api/auth/oidc/callback", q["redirect_uri"].ToString());
        Assert.True(q["state"].ToString().Length >= 22 && q["nonce"].ToString().Length >= 22);
        Assert.False(q.ContainsKey("prompt"));
        Assert.False(q.ContainsKey("client_secret"));
    }

    [Theory]
    [InlineData("login", "login")]
    [InlineData("select_account", "select_account")]
    [InlineData("consent", null)]
    [InlineData("none", null)]
    public async Task Only_safe_prompt_values_reach_Microsoft(string requested, string? expected)
    {
        using var f = new EntraFactory();
        var start = await f.NewBrowser().GetAsync("/api/auth/entra/start?prompt=" + requested);
        var q = QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        Assert.Equal(expected, q.TryGetValue("prompt", out var p) ? p.ToString() : null);
    }

    [Fact]
    public async Task A_full_sign_in_creates_the_user_and_opens_a_session()
    {
        using var f = new EntraFactory();
        f.Entra.Roles.Add("Reader");
        var browser = f.NewBrowser();

        var landing = await browser.RoundTripAsync();
        Assert.StartsWith("/login#ticket=", landing.OriginalString);
        Assert.Equal("/", Browser.Fragment(landing, "returnUrl"));
        // The short-lived external cookie is gone once the ticket exists.
        Assert.Null(browser.Cookie("__Host-aes_external"));

        var exchange = await browser.PostAsync("/api/auth/entra/exchange", new { ticket = Browser.Fragment(landing, "ticket") });
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        var body = await exchange.Content.ReadFromJsonAsync<JsonElement>();
        browser.AccessToken = body.GetProperty("accessToken").GetString();
        Assert.Equal("Pat Doe", body.GetProperty("user").GetProperty("displayName").GetString());
        Assert.Equal(FakeEntra.TenantA, body.GetProperty("user").GetProperty("tenantId").GetString());

        // Session cookies: HttpOnly refresh + readable XSRF, both __Host- / Secure / SameSite=Strict.
        var setCookies = exchange.Headers.GetValues("Set-Cookie").ToList();
        var refresh = Assert.Single(setCookies, c => c.StartsWith("__Host-aes_refresh=", StringComparison.Ordinal));
        Assert.Contains("httponly", refresh, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", refresh, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", refresh, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", refresh, StringComparison.OrdinalIgnoreCase);
        var xsrf = Assert.Single(setCookies, c => c.StartsWith("__Host-aes_xsrf=", StringComparison.Ordinal));
        Assert.DoesNotContain("httponly", xsrf, StringComparison.OrdinalIgnoreCase);

        var me = await (await browser.GetAsync("/api/auth/me")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("pat@contoso.example", me.GetProperty("email").GetString());
        Assert.Equal(new[] { "Reader" }, me.GetProperty("roles").EnumerateArray().Select(r => r.GetString()).ToArray());

        var user = await f.WithDbAsync(db => db.Users.SingleAsync());
        Assert.Equal(FakeEntra.TenantA, user.EntraTenantId);
        Assert.Equal(f.Entra.Oid, user.EntraObjectId);
        Assert.NotNull(user.LastSignInAtUtc);
        // Only hashes are stored.
        var stored = await f.WithDbAsync(db => db.RefreshTokens.SingleAsync());
        Assert.Equal(64, stored.TokenHash.Length);
        Assert.NotEqual(browser.Cookie("__Host-aes_refresh"), stored.TokenHash);
        Assert.Null(f.Entra.LastError);
    }

    [Fact]
    public async Task The_return_url_survives_the_round_trip_and_open_redirects_are_dropped()
    {
        using var f = new EntraFactory();
        var landing = await f.NewBrowser().RoundTripAsync("/api/auth/entra/start?returnUrl=" + Uri.EscapeDataString("/profile?tab=1"));
        Assert.Equal("/profile?tab=1", Browser.Fragment(landing, "returnUrl"));

        foreach (var evil in new[] { "//evil.example/x", "https://evil.example", "/\\evil.example", "javascript:alert(1)" })
        {
            var l = await f.NewBrowser().RoundTripAsync("/api/auth/entra/start?returnUrl=" + Uri.EscapeDataString(evil));
            Assert.Equal("/", Browser.Fragment(l, "returnUrl"));
        }
    }

    [Fact]
    public async Task The_ticket_works_once()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        var ticket = Browser.Fragment(await browser.RoundTripAsync(), "ticket");

        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsync("/api/auth/entra/exchange", new { ticket })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket })).StatusCode);
    }

    [Fact]
    public async Task Two_exchanges_of_the_same_ticket_at_once_open_one_session()
    {
        using var f = new EntraFactory();
        var ticket = Browser.Fragment(await f.NewBrowser().RoundTripAsync(), "ticket");

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => f.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket })));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(1, await f.WithDbAsync(db => db.UserSessions.CountAsync()));
    }

    [Fact]
    public async Task The_ticket_expires_after_two_minutes()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        var ticket = Browser.Fragment(await browser.RoundTripAsync(), "ticket");
        f.Time.Advance(TimeSpan.FromSeconds(121));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.PostAsync("/api/auth/entra/exchange", new { ticket })).StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-ticket")]
    public async Task An_unknown_ticket_is_refused(string ticket)
    {
        using var f = new EntraFactory();
        Assert.Equal(HttpStatusCode.Unauthorized, (await f.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket })).StatusCode);
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(true, "https://evil.example")]
    public async Task The_exchange_requires_this_hosts_own_origin(bool sendOrigin, string? origin)
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        var ticket = Browser.Fragment(await browser.RoundTripAsync(), "ticket");
        var response = await browser.PostAsync("/api/auth/entra/exchange", new { ticket }, origin: sendOrigin, originValue: origin);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_cross_site_fetch_cannot_exchange_a_ticket()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        var ticket = Browser.Fragment(await browser.RoundTripAsync(), "ticket");
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/entra/exchange") { Content = JsonContent.Create(new { ticket }) };
        request.Headers.Add("Origin", EntraFactory.Origin);
        request.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task The_user_is_found_by_tid_and_oid_not_by_email()
    {
        using var f = new EntraFactory();
        await f.NewBrowser().SignInAsync();
        f.Entra.Email = "pat.renamed@contoso.example";
        f.Entra.Name = "Pat Renamed";
        await f.NewBrowser().SignInAsync();

        var user = await f.WithDbAsync(db => db.Users.SingleAsync());
        Assert.Equal("pat.renamed@contoso.example", user.Email);
        Assert.Equal("Pat Renamed", user.DisplayName);

        // Same email, different object id: a different person.
        f.Entra.Oid = "44444444-4444-4444-4444-444444444444";
        await f.NewBrowser().SignInAsync();
        Assert.Equal(2, await f.WithDbAsync(db => db.Users.CountAsync()));
    }

    [Fact]
    public async Task Without_an_email_claim_the_preferred_username_is_the_display_email()
    {
        using var f = new EntraFactory();
        f.Entra.Email = null;
        f.Entra.PreferredUsername = "upn@contoso.example";
        var body = await f.NewBrowser().SignInAsync();
        Assert.Equal("upn@contoso.example", body.GetProperty("user").GetProperty("email").GetString());
    }

    [Fact]
    public async Task Without_auto_provisioning_only_existing_users_sign_in()
    {
        using var f = new EntraFactory(new() { ["Authentication:Entra:AutoProvisionUsers"] = "false" });
        var landing = await f.NewBrowser().RoundTripAsync();
        Assert.Equal("/login?ssoError=sso_not_registered", landing.OriginalString);
        Assert.Equal(0, await f.WithDbAsync(db => db.Users.CountAsync()));

        await f.WithDbAsync(async db =>
        {
            db.Users.Add(new AppUser { EntraTenantId = FakeEntra.TenantA, EntraObjectId = f.Entra.Oid!, DisplayName = "Pre-registered" });
            await db.SaveChangesAsync();
        });
        await f.NewBrowser().SignInAsync();
    }

    [Fact]
    public async Task A_disabled_user_cannot_sign_in()
    {
        using var f = new EntraFactory();
        await f.NewBrowser().SignInAsync();
        await f.WithDbAsync(async db => { (await db.Users.SingleAsync()).Disabled = true; await db.SaveChangesAsync(); });
        Assert.Equal("/login?ssoError=sso_not_allowed", (await f.NewBrowser().RoundTripAsync()).OriginalString);
    }

    [Fact]
    public async Task The_completion_step_without_a_round_trip_goes_back_to_sign_in()
    {
        using var f = new EntraFactory();
        var response = await f.NewBrowser().GetAsync("/api/auth/entra/complete");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/login?ssoError=sso_session_expired", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Config_reports_whether_Microsoft_sign_in_is_available()
    {
        using var on = new EntraFactory();
        Assert.True((await on.NewBrowser().Http.GetFromJsonAsync<JsonElement>("/api/auth/config")).GetProperty("entraEnabled").GetBoolean());

        using var off = new EntraFactory(new() { ["Authentication:Entra:Enabled"] = "false" });
        var browser = off.NewBrowser();
        Assert.False((await browser.Http.GetFromJsonAsync<JsonElement>("/api/auth/config")).GetProperty("entraEnabled").GetBoolean());
        // Without Entra the sign-in endpoints do not exist (the /api fallback answers, and requires a session).
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/entra/start")).StatusCode);
    }

    [Fact]
    public async Task The_sign_in_endpoints_are_rate_limited_per_IP()
    {
        using var f = new EntraFactory(new() { ["RateLimits:AuthPerMinute"] = "5" });
        var browser = f.NewBrowser();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 7; i++) codes.Add((await browser.GetAsync("/api/auth/entra/start")).StatusCode);
        Assert.Equal(5, codes.Count(c => c == HttpStatusCode.Redirect));
        var limited = await browser.GetAsync("/api/auth/entra/start");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("60", limited.Headers.GetValues("Retry-After").Single());
    }
}
