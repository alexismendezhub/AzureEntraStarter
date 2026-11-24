using AzureEntraStarter.Server.IntegrationTests.Support;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Testcontainers.MsSql;

namespace AzureEntraStarter.Server.IntegrationTests.Containers;

/// <summary>
/// Real SQL Server 2022 in Docker (Testcontainers). Without Docker the tests are SKIPPED with the reason, unless
/// AES_REQUIRE_CONTAINERS=1 (scripts\build-and-test.cmd and CI), where they FAIL instead.
/// </summary>
public sealed class SqlServerFixture : IAsyncLifetime
{
    public MsSqlContainer? Container { get; private set; }
    public string? Error { get; private set; }

    public async Task InitializeAsync()
    {
        try
        {
            Container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest").Build();
            await Container.StartAsync();
        }
        catch (Exception ex)
        {
            Error = $"{ex.GetType().Name}: {ex.Message}";
        }
    }

    public async Task DisposeAsync()
    {
        if (Container is not null) await Container.DisposeAsync();
    }

    public void EnsureAvailable()
    {
        if (Error is null) return;
        if (Environment.GetEnvironmentVariable("AES_REQUIRE_CONTAINERS") == "1")
            Assert.Fail("Docker is required (AES_REQUIRE_CONTAINERS=1) but SQL Server did not start: " + Error);
        Skip.If(true, "Docker not available: " + Error);
    }

    public string ConnectionString(string database) =>
        new SqlConnectionStringBuilder(Container!.GetConnectionString()) { InitialCatalog = database }.ConnectionString;
}

public sealed class SqlServerTests(SqlServerFixture sql) : IClassFixture<SqlServerFixture>
{
    private EntraFactory Factory(string database) => new(new()
    {
        ["Database:Provider"] = "SqlServer",
        ["Database:MigrateOnStartup"] = "true",
        ["ConnectionStrings:Default"] = sql.ConnectionString(database)
    });

    [SkippableFact]
    public async Task Migrations_apply_and_the_whole_flow_works_on_SQL_Server()
    {
        sql.EnsureAvailable();
        using var f = Factory("aes_flow_" + Guid.NewGuid().ToString("N")[..8]);
        var browser = f.NewBrowser();
        await browser.SignInAsync();
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.RefreshAsync()).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsync("/api/auth/logout", xsrf: true, bearer: false)).StatusCode);

        Assert.Empty(await f.WithDbAsync(db => db.Database.GetPendingMigrationsAsync()));
        // The Data Protection key ring (it protects the sign-in round trip) is stored in the shared database.
        Assert.True(await f.WithDbAsync(db => db.DataProtectionKeys.CountAsync()) > 0);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/health/ready")).StatusCode);
    }

    [SkippableFact]
    public async Task Two_instances_share_sessions_and_a_ticket_is_still_used_once()
    {
        sql.EnsureAvailable();
        var database = "aes_shared_" + Guid.NewGuid().ToString("N")[..8];
        using var a = Factory(database);
        using var b = Factory(database);
        _ = a.Services; // A migrates first

        // The round trip starts on A and finishes on B: the shared key ring decrypts A's state and cookies.
        var browserA = a.NewBrowser();
        var start = await browserA.GetAsync("/api/auth/entra/start");
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        b.Entra.Nonce = state["nonce"].ToString();
        var browserB = b.NewBrowser();
        browserB.Cookies.Add(browserA.Cookies.GetAllCookies());
        var callback = await browserB.Http.PostAsync("/api/auth/oidc/callback", new FormUrlEncodedContent(new Dictionary<string, string> { ["code"] = "good-code", ["state"] = state["state"].ToString() }));
        Assert.Equal("/api/auth/entra/complete", callback.Headers.Location?.OriginalString);
        var complete = await browserB.GetAsync(callback.Headers.Location!.OriginalString);
        var ticket = Browser.Fragment(complete.Headers.Location!, "ticket");

        var results = await Task.WhenAll(
            a.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket }),
            b.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket }),
            a.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket }),
            b.NewBrowser().PostAsync("/api/auth/entra/exchange", new { ticket }));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
    }
}
