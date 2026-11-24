using System.Text.Json;
using AzureEntraStarter.Infrastructure.Data;
using AzureEntraStarter.Server.Authentication;
using AzureEntraStarter.Server.IntegrationTests.Support;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AzureEntraStarter.Server.IntegrationTests;

/// <summary>The application's session after the Microsoft sign-in: refresh rotation, reuse detection, limits and sign-out.</summary>
public sealed class SessionTests
{
    [Fact]
    public async Task Refresh_rotates_the_credential_and_issues_a_new_access_token()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var firstRefresh = browser.Cookie(AuthCookies.RefreshCookieName);
        var firstToken = browser.AccessToken;

        var response = await browser.RefreshAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotEqual(firstRefresh, browser.Cookie(AuthCookies.RefreshCookieName));
        Assert.NotEqual(firstToken, browser.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/auth/me")).StatusCode);
        // Same session (sid), a new refresh row; the old one is marked rotated.
        Assert.Equal(1, await f.WithDbAsync(db => db.UserSessions.CountAsync()));
        Assert.Equal(1, await f.WithDbAsync(db => db.RefreshTokens.CountAsync(x => x.RotatedAtUtc != null)));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task Refresh_requires_this_hosts_origin_and_the_xsrf_header(bool origin, bool xsrf)
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var response = await browser.PostAsync("/api/auth/refresh", origin: origin, xsrf: xsrf, bearer: false);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A_wrong_xsrf_value_is_refused()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/refresh") { Content = JsonContent.Create(new { }) };
        request.Headers.Add("Origin", EntraFactory.Origin);
        request.Headers.Add(AuthCookies.XsrfHeaderName, new string('0', 64));
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(request, bearer: false)).StatusCode);
    }

    [Fact]
    public async Task A_first_visit_without_cookies_gets_no_content()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        // No refresh cookie yet: the XSRF check cannot pass either, and the answer is a quiet 403.
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PostAsync("/api/auth/refresh", bearer: false)).StatusCode);
    }

    [Fact]
    public async Task A_rotated_credential_replayed_after_the_grace_period_ends_the_session()
    {
        using var f = new EntraFactory();
        var victim = f.NewBrowser();
        await victim.SignInAsync();
        var stolenRefresh = victim.Cookie(AuthCookies.RefreshCookieName)!;
        var stolenXsrf = victim.Cookie(AuthCookies.XsrfCookieName)!;
        Assert.Equal(HttpStatusCode.OK, (await victim.RefreshAsync()).StatusCode);

        // Within the grace period (another tab) the old credential is ignored, not punished.
        var attacker = f.NewBrowser();
        attacker.Cookies.Add(new Uri(EntraFactory.Origin), new Cookie(AuthCookies.RefreshCookieName, stolenRefresh) { Secure = true });
        attacker.Cookies.Add(new Uri(EntraFactory.Origin), new Cookie(AuthCookies.XsrfCookieName, stolenXsrf) { Secure = true });
        Assert.Equal(HttpStatusCode.NoContent, (await attacker.RefreshAsync()).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await victim.GetAsync("/api/auth/me")).StatusCode);

        // Later, the replay is theft: the whole session ends, for the thief and for the victim.
        f.Time.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(HttpStatusCode.NoContent, (await attacker.RefreshAsync()).StatusCode);
        Assert.NotNull(await f.WithDbAsync(db => db.UserSessions.Select(s => s.RevokedAtUtc).SingleAsync()));
        Assert.Equal(HttpStatusCode.NoContent, (await victim.RefreshAsync()).StatusCode);
        Assert.Null(victim.Cookie(AuthCookies.RefreshCookieName));
    }

    [Fact]
    public async Task An_idle_refresh_credential_expires()
    {
        using var f = new EntraFactory(new() { ["Session:RefreshTokenMinutes"] = "60" });
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        f.Time.Advance(TimeSpan.FromMinutes(61));
        Assert.Equal(HttpStatusCode.NoContent, (await browser.RefreshAsync()).StatusCode);
        Assert.Null(browser.Cookie(AuthCookies.RefreshCookieName));
    }

    [Fact]
    public async Task The_session_has_an_absolute_limit_whatever_the_activity()
    {
        using var f = new EntraFactory(new() { ["Session:MaxSessionHours"] = "1", ["Session:RefreshTokenMinutes"] = "60" });
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        f.Time.Advance(TimeSpan.FromMinutes(40));
        Assert.Equal(HttpStatusCode.OK, (await browser.RefreshAsync()).StatusCode);
        // The new credential never outlives the session.
        var newest = await f.WithDbAsync(db => db.RefreshTokens.Where(x => x.RotatedAtUtc == null).SingleAsync());
        var session = await f.WithDbAsync(db => db.UserSessions.SingleAsync());
        Assert.Equal(session.ExpiresAtUtc, newest.ExpiresAtUtc);
        f.Time.Advance(TimeSpan.FromMinutes(21));
        Assert.Equal(HttpStatusCode.NoContent, (await browser.RefreshAsync()).StatusCode);
    }

    [Fact]
    public async Task Sign_out_revokes_the_session_and_the_access_token_stops_at_once()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var token = browser.AccessToken;

        var logout = await browser.PostAsync("/api/auth/logout", xsrf: true, bearer: false);
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        Assert.Equal(JsonValueKind.Null, (await logout.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("microsoftSignOutUrl").ValueKind);
        Assert.Null(browser.Cookie(AuthCookies.RefreshCookieName));

        browser.AccessToken = token;
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Sign_out_with_a_session_requires_origin_and_xsrf()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PostAsync("/api/auth/logout", xsrf: false, bearer: false)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Sign_out_can_also_end_the_Microsoft_session()
    {
        using var f = new EntraFactory(new() { ["Authentication:Entra:SignOutOfMicrosoft"] = "true" });
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var body = await (await browser.PostAsync("/api/auth/logout", xsrf: true, bearer: false)).Content.ReadFromJsonAsync<JsonElement>();
        var url = new Uri(body.GetProperty("microsoftSignOutUrl").GetString()!);
        Assert.StartsWith(FakeEntra.EndSessionEndpoint, url.AbsoluteUri);
        var q = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(url.Query);
        Assert.Equal("https://localhost/signed-out", q["post_logout_redirect_uri"].ToString());
        Assert.Equal(FakeEntra.ClientId, q["client_id"].ToString());
    }

    [Fact]
    public async Task A_new_sign_in_in_the_same_browser_ends_its_previous_session()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        var first = browser.AccessToken;
        await browser.SignInAsync();
        browser.AccessToken = first;
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Disabling_a_user_ends_its_sessions_immediately()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        await f.WithDbAsync(async db => { (await db.Users.SingleAsync()).Disabled = true; await db.SaveChangesAsync(); });

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await browser.RefreshAsync()).StatusCode);
        Assert.Null(browser.Cookie(AuthCookies.RefreshCookieName));
    }

    [Fact]
    public async Task Cleanup_deletes_used_tickets_and_ended_sessions_after_a_day()
    {
        using var f = new EntraFactory();
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        await browser.PostAsync("/api/auth/logout", xsrf: true, bearer: false);
        await f.NewBrowser().SignInAsync();

        var cleanup = ActivatorUtilities.CreateInstance<SessionCleanupService>(f.Services);
        Assert.Equal(0, await cleanup.RunOnceAsync(CancellationToken.None));
        f.Time.Advance(TimeSpan.FromHours(25));
        // A day after: the two tickets and the signed-out session; the open session (12 h) is not a day old yet.
        Assert.Equal(3, await cleanup.RunOnceAsync(CancellationToken.None));
        f.Time.Advance(TimeSpan.FromHours(12));
        Assert.Equal(1, await cleanup.RunOnceAsync(CancellationToken.None));
        Assert.Equal(0, await f.WithDbAsync(db => db.RefreshTokens.CountAsync()));
        Assert.Equal(1, await f.WithDbAsync(db => db.Users.CountAsync()));
    }
}
