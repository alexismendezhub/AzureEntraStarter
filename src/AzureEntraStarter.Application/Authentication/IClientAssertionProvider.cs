using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AzureEntraStarter.Application.Authentication;

/// <summary>
/// Proves this application's identity at Microsoft's token endpoint without a client secret (private_key_jwt,
/// RFC 7523): a certificate the application holds, or a managed identity used as a federated identity credential.
/// </summary>
public interface IClientAssertionProvider
{
    Task<string> GetAssertionAsync(string tokenEndpoint, CancellationToken cancellationToken);
}
