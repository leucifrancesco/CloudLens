using Azure.Core;
using Azure.Identity;

namespace CloudLens.Core.Azure;

public sealed class AzureAuthenticator
{
    private const string AzureManagementScope =
        "https://management.azure.com/.default";

    // Microsoft Azure CLI public client application.
    // Utilizzata per l'autenticazione interattiva locale.
    private const string AzureCliClientId =
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

    private readonly HttpClient _http;

    private InteractiveBrowserCredential? _interactiveCredential;

    public AzureAuthenticator(HttpClient http)
    {
        _http = http;
    }


    // ---------------------------------------------------------
    // SERVICE PRINCIPAL
    // ---------------------------------------------------------

    public Task<string> GetAccessTokenAsync(
        string tenantId,
        string clientId,
        string clientSecret,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));

        if (string.IsNullOrWhiteSpace(clientId))
            throw new ArgumentException(
                "Client ID obbligatorio.",
                nameof(clientId));

        if (string.IsNullOrWhiteSpace(clientSecret))
            throw new ArgumentException(
                "Client Secret obbligatorio.",
                nameof(clientSecret));

        var credential =
            new ClientSecretCredential(
                tenantId,
                clientId,
                clientSecret);

        return GetTokenAsync(
            credential,
            cancellationToken);
    }


    // ---------------------------------------------------------
    // INTERACTIVE BROWSER
    // ---------------------------------------------------------

    public Task<string> GetInteractiveAccessTokenAsync(
        string tenantId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));

        // IMPORTANTE:
        // la credenziale viene creata una sola volta.
        //
        // Azure.Identity mantiene la cache del token e può
        // rinnovarlo senza richiedere nuovamente il login.
        _interactiveCredential ??=
            new InteractiveBrowserCredential(
                new InteractiveBrowserCredentialOptions
                {
                    TenantId = tenantId,
                    ClientId = AzureCliClientId,
                    RedirectUri = new Uri("http://localhost")
                });

        return GetTokenAsync(
            _interactiveCredential,
            cancellationToken);
    }


    // ---------------------------------------------------------
    // TOKEN
    // ---------------------------------------------------------

    private static async Task<string> GetTokenAsync(
        TokenCredential credential,
        CancellationToken cancellationToken)
    {
        var token =
            await credential.GetTokenAsync(
                new TokenRequestContext(
                [
                    AzureManagementScope
                ]),
                cancellationToken);

        if (string.IsNullOrWhiteSpace(token.Token))
        {
            throw new InvalidOperationException(
                "Azure non ha restituito un access token.");
        }

        return token.Token;
    }
}