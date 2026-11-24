# Azure Entra Starter

ASP.NET Core 10 + Angular 22 starter where users sign in **only with Microsoft Entra ID** (work or school accounts).
There are no local passwords, no other identity providers and no device checks: just a hardened Entra sign-in, the
application's own session, and app roles from Entra.

## How to use it

Open the application, click **Sign in with Microsoft** and sign in with an account of your directory. The sample
administration page needs the Entra app role `Admin`.

## Configuration

Signing in needs an application registered in your Microsoft Entra directory, so this comes before the first run.

### Register the application in Microsoft Entra

**Azure portal:** *Microsoft Entra ID → App registrations → New registration*

1. Name: `AzureEntraStarter (dev)`. Supported account types: **Accounts in this organizational directory only**
   (single tenant).
2. Redirect URI, platform **Web**: `https://localhost:63431/api/auth/oidc/callback` (the Angular dev server that Visual
   Studio opens; the proxy forwards `/api` to the server with the same host).
   Add `https://localhost:7190/api/auth/oidc/callback` too if you also run the server alone.
3. *Certificates & secrets → New client secret* (development only).
4. *Authentication*: leave **ID tokens** and **Access tokens** (implicit grant) **unchecked**.
5. Optional, for `SignOutOfMicrosoft`: add `https://localhost:63431/signed-out` as a redirect URI.
6. Note the **Application (client) ID** and the **Directory (tenant) ID**.

**Azure CLI** (same result):

```powershell
$app = az ad app create --display-name "AzureEntraStarter (dev)" --sign-in-audience AzureADMyOrg `
  --web-redirect-uris https://localhost:63431/api/auth/oidc/callback https://localhost:7190/api/auth/oidc/callback `
  --app-roles '@deploy/entra/app-roles.json' --query appId -o tsv
az ad sp create --id $app
az ad app credential reset --id $app --display-name dev --years 1 --query password -o tsv   # the dev client secret
az account show --query tenantId -o tsv                                                     # the directory id
```

### Configure the server (user-secrets, never appsettings)

```powershell
cd src\AzureEntraStarter.Server
dotnet user-secrets set "Authentication:Entra:Enabled" "true"
dotnet user-secrets set "Authentication:Entra:Authority" "https://login.microsoftonline.com/<directory-id>/v2.0"
dotnet user-secrets set "Authentication:Entra:ClientId" "<application-id>"
dotnet user-secrets set "Authentication:Entra:ClientSecret" "<client-secret>"
```

In Development an empty `Jwt:SigningKey` is replaced by a temporary key (a warning is logged). To keep sessions across
restarts, generate a real one:

```powershell
dotnet run --project src\AzureEntraStarter.Server -- --generate-signing-key
dotnet user-secrets set "Jwt:SigningKey" "<the printed key>" --project src\AzureEntraStarter.Server
```

## How to run it

**Requirements:** .NET SDK 10, Node.js 22.22.3+ or 24.15+, SQL Server LocalDB (installed with Visual Studio), and a
Microsoft Entra directory where you can register an application.

Open `AzureEntraStarter.slnx` in Visual Studio and press **F5** (profile `https`), or:

```powershell
dotnet run --project src\AzureEntraStarter.Server --launch-profile https
```

The application opens at `https://localhost:63431`. The database `AzureEntraStarter` is created in LocalDB and
migrated at startup (Development only).

## Tests

```cmd
scripts\build-and-test.cmd
```

It runs the build, the .NET tests (Docker is required for the SQL Server tests), the Angular tests, the Angular
production build and the real-server smoke test.

## License and disclaimer

Licensed under the [Apache License 2.0](LICENSE): anyone may use, modify and distribute it, including commercially.

It is provided as an example, "as is", without warranty of any kind. Review and test it before using it in
production; the authors are not liable for any damage that results from its use.
