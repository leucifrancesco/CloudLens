using System.Text.Json;
using CloudLens.Core.Analysis;

namespace CloudLens.Core.Azure;

public sealed class AzureCollector
{
    private readonly HttpClient _http;

    private readonly AssessmentEngine _assessmentEngine;


    public AzureCollector(
        HttpClient http)
    {
        _http =
            http ?? throw new ArgumentNullException(
                nameof(http));

        _assessmentEngine =
            new AssessmentEngine(
            [
                new SecurityAnalyzer(),
                new CostAnalyzer(),
                new OperationsAnalyzer(),
                new ArchitectureAnalyzer()
            ]);
    }


    // =========================================================
    // INTERACTIVE AUTHENTICATION + SUBSCRIPTION DISCOVERY
    // =========================================================

    public async Task<List<AzureSubscription>>
        AuthenticateInteractiveAndListSubscriptionsAsync(
            string tenantId,
            CancellationToken cancellationToken = default)
    {
        var authenticator =
            new AzureAuthenticator(_http);

        var token =
            await authenticator
                .GetInteractiveAccessTokenAsync(
                    tenantId,
                    cancellationToken);

        var client =
            new AzureResourceClient(
                _http,
                token);

        return await client.GetSubscriptionsAsync(
            cancellationToken);
    }


    // =========================================================
    // INTERACTIVE ASSESSMENT
    //
    // IMPORTANTE:
    // Il token viene ricevuto dall'esterno.
    // NON viene eseguita una nuova autenticazione.
    // =========================================================

    public async Task<ScanResult>
        ScanInteractiveAsync(
            string token,
            AzureSubscription subscription,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException(
                "Access token obbligatorio.",
                nameof(token));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(
                nameof(subscription));
        }

        var client =
            new AzureResourceClient(
                _http,
                token);


        // -----------------------------------------------------
        // RESOURCE DISCOVERY
        // -----------------------------------------------------

        var resources =
            await client.GetResourcesAsync(
                subscription.Id,
                cancellationToken);


        // -----------------------------------------------------
        // ANALYSIS
        // -----------------------------------------------------

        return _assessmentEngine.Analyze(
            resources,
            subscription);
    }


    // =========================================================
    // SERVICE PRINCIPAL AUTHENTICATION
    //
    // Manteniamo questa modalità per utilizzi futuri,
    // anche se la GUI attualmente utilizza Interactive Login.
    // =========================================================

    public async Task<List<AzureSubscription>>
        AuthenticateAndListSubscriptionsAsync(
            string tenantId,
            string clientId,
            string clientSecret,
            CancellationToken cancellationToken = default)
    {
        var authenticator =
            new AzureAuthenticator(_http);

        var token =
            await authenticator.GetAccessTokenAsync(
                tenantId,
                clientId,
                clientSecret,
                cancellationToken);

        var client =
            new AzureResourceClient(
                _http,
                token);

        return await client.GetSubscriptionsAsync(
            cancellationToken);
    }


    // =========================================================
    // SERVICE PRINCIPAL SCAN
    // =========================================================

    public async Task<ScanResult>
        ScanAsync(
            string tenantId,
            string clientId,
            string clientSecret,
            AzureSubscription subscription,
            CancellationToken cancellationToken = default)
    {
        var authenticator =
            new AzureAuthenticator(_http);

        var token =
            await authenticator.GetAccessTokenAsync(
                tenantId,
                clientId,
                clientSecret,
                cancellationToken);

        return await ScanWithTokenAsync(
            token,
            subscription,
            cancellationToken);
    }


    // =========================================================
    // COMMON TOKEN-BASED SCAN
    // =========================================================

    private async Task<ScanResult>
        ScanWithTokenAsync(
            string token,
            AzureSubscription subscription,
            CancellationToken cancellationToken)
    {
        var client =
            new AzureResourceClient(
                _http,
                token);


        // -----------------------------------------------------
        // RESOURCE DISCOVERY
        // -----------------------------------------------------

        var resources =
            await client.GetResourcesAsync(
                subscription.Id,
                cancellationToken);


        // -----------------------------------------------------
        // ANALYSIS
        // -----------------------------------------------------

        return _assessmentEngine.Analyze(
            resources,
            subscription);
    }
}