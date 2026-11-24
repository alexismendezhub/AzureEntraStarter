using System.Net.Http.Headers;
using System.Text.Json;
using AzureEntraStarter.Infrastructure.Data;
using AzureEntraStarter.Server.Authentication;
using AzureEntraStarter.Server.Security;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AzureEntraStarter.Server.IntegrationTests.Support;

/// <summary>
/// The real application (environment "Testing", in-memory database) signing in against <see cref="FakeEntra"/>.
/// Settings override appsettings; <see cref="Services"/> can add or replace registrations.
/// </summary>
public sealed class EntraFactory : WebApplicationFactory<Program>
{
    public const string Origin = "https://localhost";

    public FakeEntra Entra { get; } = new();
    public FakeTimeProvider Time { get; } = new(DateTimeOffset.UtcNow);
    public Dictionary<string, string?> Settings { get; }
    public Action<IServiceCollection>? TestServices { get; set; }
    public string Environment { get; set; } = "Testing";

    public EntraFactory(Dictionary<string, string?>? overrides = null)
    {
        Settings = new Dictionary<string, string?>
        {
            ["Database:Provider"] = "InMemory",
            ["Database:Name"] = "aes-" + Guid.NewGuid().ToString("N"),
            ["Authentication:Entra:Enabled"] = "true",
            ["Authentication:Entra:Authority"] = $"{FakeEntra.Host}/{FakeEntra.TenantA}/v2.0",
            ["Authentication:Entra:ClientId"] = FakeEntra.ClientId,
            ["Authentication:Entra:ClientCredentialType"] = "ClientSecret",
            ["Authentication:Entra:ClientSecret"] = FakeEntra.ClientSecret,
            ["RateLimits:AuthPerMinute"] = "1000",
            ["RateLimits:SessionPerMinute"] = "1000",
        };
        foreach (var (key, value) in overrides ?? []) Settings[key] = value;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(Environment);
        // UseSetting (not ConfigureAppConfiguration): Program reads some settings while it builds the services, and
        // only host settings are already visible at that point with the minimal hosting model.
        foreach (var (key, value) in Settings) builder.UseSetting(key, value);
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Time);
            // The background cleanup is exercised directly by its own test.
            services.RemoveAll<IHostedService>();
            services.PostConfigure<OpenIdConnectOptions>(AzureEntraStarter.Server.Authentication.AuthenticationSchemes.Entra, o =>
            {
                var configuration = new OpenIdConnectConfiguration
                {
                    Issuer = $"{FakeEntra.Host}/{{tenantid}}/v2.0",
                    AuthorizationEndpoint = FakeEntra.AuthorizeEndpoint,
                    TokenEndpoint = FakeEntra.TokenEndpoint,
                    EndSessionEndpoint = FakeEntra.EndSessionEndpoint
                };
                configuration.SigningKeys.Add(Entra.SigningKey);
                o.Configuration = configuration;
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
                o.Backchannel = new HttpClient(Entra);
            });
            TestServices?.Invoke(services);
        });
    }

    public Browser NewBrowser() => new(this);

    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> action)
    {
        await using var scope = Services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    public Task WithDbAsync(Func<AppDbContext, Task> action) => WithDbAsync(async db => { await action(db); return true; });
}

/// <summary>A browser: keeps cookies (Secure, __Host-), never follows redirects, sends this host's Origin when asked.</summary>
public sealed class Browser
{
    private readonly EntraFactory _factory;
    public CookieContainer Cookies { get; } = new();
    public HttpClient Http { get; }
    public string? AccessToken { get; set; }

    public Browser(EntraFactory factory)
    {
        _factory = factory;
        Http = new HttpClient(new CookieContainerHandler(Cookies) { InnerHandler = factory.Server.CreateHandler() })
        {
            BaseAddress = new Uri(EntraFactory.Origin)
        };
    }

    public string? Cookie(string name) => Cookies.GetCookies(new Uri(EntraFactory.Origin)).FirstOrDefault(c => c.Name == name)?.Value;

    public Task<HttpResponseMessage> GetAsync(string url, bool bearer = true) => SendAsync(new HttpRequestMessage(HttpMethod.Get, url), bearer);

    public Task<HttpResponseMessage> PostAsync(string url, object? body = null, bool origin = true, bool xsrf = false, string? originValue = null, bool bearer = true)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(body ?? new { }) };
        if (origin) request.Headers.Add("Origin", originValue ?? EntraFactory.Origin);
        if (xsrf && Cookie(AuthCookies.XsrfCookieName) is { } value) request.Headers.Add(AuthCookies.XsrfHeaderName, value);
        return SendAsync(request, bearer);
    }

    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, bool bearer = true)
    {
        if (bearer && AccessToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
        return Http.SendAsync(request);
    }

    /// <summary>Start → Microsoft's form POST to the callback → completion. Returns the final redirect (normally /login#ticket=…).</summary>
    public async Task<Uri> RoundTripAsync(string startUrl = "/api/auth/entra/start", Action<IDictionary<string, string>>? alterCallback = null)
    {
        var start = await GetAsync(startUrl);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var authorize = QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        _factory.Entra.Nonce = authorize["nonce"].ToString();
        var form = new Dictionary<string, string> { ["code"] = "good-code", ["state"] = authorize["state"].ToString() };
        alterCallback?.Invoke(form);
        var callback = await Http.PostAsync("/api/auth/oidc/callback", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        var location = callback.Headers.Location!;
        if (!location.OriginalString.StartsWith("/api/auth/entra/complete", StringComparison.Ordinal)) return location;
        var complete = await GetAsync(location.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, complete.StatusCode);
        return complete.Headers.Location!;
    }

    public static string Fragment(Uri location, string name) => QueryHelpers.ParseQuery(location.OriginalString.Split('#', 2)[1])[name].ToString();

    /// <summary>A complete sign-in: round trip and ticket exchange. Keeps the access token for the next requests.</summary>
    public async Task<JsonElement> SignInAsync()
    {
        var landing = await RoundTripAsync();
        Assert.StartsWith("/login#", landing.OriginalString);
        var exchange = await PostAsync("/api/auth/entra/exchange", new { ticket = Fragment(landing, "ticket") });
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        var body = await exchange.Content.ReadFromJsonAsync<JsonElement>();
        AccessToken = body.GetProperty("accessToken").GetString();
        return body;
    }

    public async Task<HttpResponseMessage> RefreshAsync()
    {
        var response = await PostAsync("/api/auth/refresh", xsrf: true, bearer: false);
        if (response.StatusCode == HttpStatusCode.OK)
            AccessToken = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString();
        return response;
    }
}
