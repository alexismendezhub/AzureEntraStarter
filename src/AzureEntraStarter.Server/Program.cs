using AzureEntraStarter.Infrastructure;
using AzureEntraStarter.Infrastructure.Authentication;
using AzureEntraStarter.Infrastructure.Data;
using AzureEntraStarter.Server;
using AzureEntraStarter.Server.Authentication;
using AzureEntraStarter.Server.Endpoints;
using AzureEntraStarter.Server.Middleware;
using AzureEntraStarter.Server.Security;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

// dotnet AzureEntraStarter.Server.dll --generate-signing-key → a new P-256 private key for Jwt:SigningKey (base64 PKCS#8).
if (args.Contains("--generate-signing-key"))
{
    using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
    Console.WriteLine(Convert.ToBase64String(key.ExportPkcs8PrivateKey()));
    return;
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddEntraAuthentication(builder.Configuration, builder.Environment);
builder.Services.AddAuthRateLimits(builder.Configuration);
builder.Services.AddProblemDetails();

var app = builder.Build();

StartupValidation.Validate(app);
await app.PrepareDatabaseAsync();
if (app.Services.GetRequiredService<TokenSigningKeys>().IsEphemeral)
    app.Logger.LogWarning("Jwt:SigningKey is empty: using a temporary key (Development only). Access tokens end when the process stops.");

// Behind App Service / a reverse proxy set ASPNETCORE_FORWARDEDHEADERS_ENABLED=true so the scheme and host are the public ones.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}
app.UseHttpsRedirection();
app.UseSecurityHeaders();

// Angular files ("Angular and ASP.NET Core" template)
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseMiddleware<LiveSessionMiddleware>();
app.UseRateLimiter();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapSampleEndpoints();
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") }).AllowAnonymous();

app.MapFallback("/api/{**rest}", () => Results.NotFound());
app.MapFallbackToFile("/index.html").AllowAnonymous();

await app.RunAsync();

public partial class Program;
