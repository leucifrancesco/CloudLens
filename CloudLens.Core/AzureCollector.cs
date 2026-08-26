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

        return await ScanWithTokenAsync(
            token,
            subscription,
            cancellationToken);
    }


    // =========================================================
    // SERVICE PRINCIPAL AUTHENTICATION
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
        // METRIC COLLECTION
        // -----------------------------------------------------

        var monitorClient =
            new AzureMonitorClient(
                _http,
                token);

        var metricProfiles =
            await monitorClient.GetMetricsAsync(
                resources,
                cancellationToken);


        // -----------------------------------------------------
        // ANALYSIS
        // -----------------------------------------------------

        var result =
            _assessmentEngine.Analyze(
                resources,
                subscription);


        // -----------------------------------------------------
        // METRICS
        // -----------------------------------------------------

        result.MetricProfiles =
            metricProfiles;


        // -----------------------------------------------------
        // DIAGNOSTICS
        // -----------------------------------------------------

        PrintScanDiagnostics(
            resources,
            metricProfiles);


        return result;
    }


    // =========================================================
    // DIAGNOSTICS
    // =========================================================

    private static void PrintScanDiagnostics(
        IReadOnlyList<JsonElement> resources,
        IReadOnlyList<MetricProfile> metricProfiles)
    {
        Console.WriteLine();

        Console.WriteLine(
            "=========================================================");

        Console.WriteLine(
            "CLOUDLENS - AZURE DISCOVERY");

        Console.WriteLine(
            "=========================================================");

        Console.WriteLine(
            $"Risorse scoperte : {resources.Count}");

        Console.WriteLine(
            $"Metriche raccolte: {metricProfiles.Count}");

        Console.WriteLine();


        // -----------------------------------------------------
        // RESOURCES BY TYPE
        // -----------------------------------------------------

        Console.WriteLine(
            "RISORSE PER RESOURCE TYPE:");

        Console.WriteLine();

        var resourceGroups =
            resources
                .GroupBy(
                    x =>
                        x.TryGetProperty(
                            "type",
                            out var type)
                            ? type.GetString() ?? "Unknown"
                            : "Unknown",
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    x => x.Count());

        foreach (var group in resourceGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");
        }


        Console.WriteLine();


        // -----------------------------------------------------
        // METRICS BY RESOURCE TYPE
        // -----------------------------------------------------

        Console.WriteLine(
            "METRICHE PER RESOURCE TYPE:");

        Console.WriteLine();

        var metricGroups =
            metricProfiles
                .GroupBy(
                    x => x.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    x => x.Count());

        foreach (var group in metricGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");
        }


        Console.WriteLine();


        // -----------------------------------------------------
        // UNIQUE METRIC TYPES
        // -----------------------------------------------------

        Console.WriteLine(
            "METRICHE UNICHE:");

        Console.WriteLine();

        var metricNames =
            metricProfiles
                .GroupBy(
                    x =>
                        $"{x.ResourceType}|{x.MetricName}",
                    StringComparer.OrdinalIgnoreCase)
                .Select(
                    x => x.First())
                .OrderBy(
                    x => x.ResourceType)
                .ThenBy(
                    x => x.MetricName)
                .ToList();

        foreach (var metric in
                 metricNames.Take(100))
        {
            Console.WriteLine(
                $"{metric.ResourceType} | " +
                $"{metric.MetricName} | " +
                $"{metric.Unit}");
        }


        Console.WriteLine();


        // -----------------------------------------------------
        // FIRST 20 PROFILES
        // -----------------------------------------------------

        Console.WriteLine(
            "PRIME 20 METRICHE RACCOLTE:");

        Console.WriteLine();

        foreach (var metric in
                 metricProfiles.Take(20))
        {
            Console.WriteLine(
                $"{metric.ResourceName} | " +
                $"{metric.MetricDisplayName} | " +
                $"Avg={metric.Average:F2} | " +
                $"Min={metric.Minimum:F2} | " +
                $"Max={metric.Maximum:F2} | " +
                $"Samples={metric.SampleCount}");
        }


        Console.WriteLine();

        Console.WriteLine(
            "=========================================================");
    }
}