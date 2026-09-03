using System.Diagnostics;
using CloudLens.Core;
using CloudLens.Core.Analysis;

namespace CloudLens.Core.Azure;

public sealed class AzureCollector
{
    private readonly HttpClient _http;
    private readonly AssessmentEngine _assessmentEngine;

    public AzureCollector(HttpClient http)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));

        _assessmentEngine = new AssessmentEngine(
        [
            new SecurityAnalyzer(),
            new CostAnalyzer(),
            new OperationsAnalyzer(),
            new ArchitectureAnalyzer(),
            new KeyVaultAnalyzer(),
            new StorageAnalyzer(),
            new VirtualMachineAnalyzer()
        ]);
    }

    public async Task<List<AzureSubscription>>
        AuthenticateInteractiveAndListSubscriptionsAsync(
            string tenantId,
            CancellationToken cancellationToken = default)
    {
        var authenticator = new AzureAuthenticator(_http);

        var token = await authenticator
            .GetInteractiveAccessTokenAsync(
                tenantId,
                cancellationToken);

        var client = new AzureResourceClient(
            _http,
            token);

        return await client.GetSubscriptionsAsync(
            cancellationToken);
    }

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

    public async Task<List<AzureSubscription>>
        AuthenticateAndListSubscriptionsAsync(
            string tenantId,
            string clientId,
            string clientSecret,
            CancellationToken cancellationToken = default)
    {
        var authenticator = new AzureAuthenticator(_http);

        var token = await authenticator.GetAccessTokenAsync(
            tenantId,
            clientId,
            clientSecret,
            cancellationToken);

        var client = new AzureResourceClient(
            _http,
            token);

        return await client.GetSubscriptionsAsync(
            cancellationToken);
    }

    public async Task<ScanResult>
        ScanAsync(
            string tenantId,
            string clientId,
            string clientSecret,
            AzureSubscription subscription,
            CancellationToken cancellationToken = default)
    {
        if (subscription == null)
        {
            throw new ArgumentNullException(
                nameof(subscription));
        }

        var authenticator = new AzureAuthenticator(_http);

        var token = await authenticator.GetAccessTokenAsync(
            tenantId,
            clientId,
            clientSecret,
            cancellationToken);

        return await ScanWithTokenAsync(
            token,
            subscription,
            cancellationToken);
    }

    private async Task<ScanResult>
        ScanWithTokenAsync(
            string token,
            AzureSubscription subscription,
            CancellationToken cancellationToken)
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

        var stopwatch = Stopwatch.StartNew();

        var client = new AzureResourceClient(
            _http,
            token);

        var resources =
            await client.GetAzureResourcesAsync(
                subscription.Id,
                cancellationToken);

        var enricher = new AzureResourceEnricher(
            _http,
            token);

        await enricher.EnrichAsync(
            resources,
            cancellationToken);

        var enrichmentStats =
            BuildEnrichmentStats(resources);

        var relationshipBuilder =
            new AzureRelationshipBuilder();

        relationshipBuilder.Build(resources);

        var resourceGraph =
            new AzureResourceGraph(resources);

        var monitorClient =
            new AzureMonitorClient(
                _http,
                token);

        var rawResources =
            resources
                .Select(resource => resource.Raw)
                .ToList();

        var metricProfiles =
            await monitorClient.GetMetricsAsync(
                rawResources,
                cancellationToken);

        var result =
            _assessmentEngine.Analyze(
                resources,
                subscription);

        result.Resources.AddRange(resources);

        result.MetricProfiles =
            metricProfiles;

        result.Enrichment =
            enrichmentStats;

        stopwatch.Stop();

        PrintScanDiagnostics(
            resources,
            metricProfiles,
            resourceGraph,
            result,
            stopwatch.Elapsed);

        return result;
    }

    private static EnrichmentStats
        BuildEnrichmentStats(
            IReadOnlyList<AzureResource> resources)
    {
        var successful =
            resources.Count(
                resource =>
                    resource.Enrichment?.Success == true);

        var failed =
            resources.Count(
                resource =>
                    resource.Enrichment != null &&
                    resource.Enrichment.Success == false);

        var notProcessed =
            resources.Count(
                resource =>
                    resource.Enrichment == null);

        var successRate =
            resources.Count == 0
                ? 0
                : successful * 100.0 /
                  resources.Count;

        var apiVersions =
            resources
                .Where(
                    resource =>
                        resource.Enrichment?.Success == true)
                .Select(
                    resource =>
                        resource.Enrichment!.ApiVersion)
                .Where(
                    version =>
                        !string.IsNullOrWhiteSpace(version))
                .GroupBy(
                    version =>
                        version!,
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group =>
                        group.Key,
                    group =>
                        group.Count(),
                    StringComparer.OrdinalIgnoreCase);

        var errors =
            resources
                .Where(
                    resource =>
                        resource.Enrichment != null &&
                        resource.Enrichment.Success == false)
                .Where(
                    resource =>
                        !string.IsNullOrWhiteSpace(
                            resource.Enrichment!.Error))
                .ToDictionary(
                    resource =>
                        resource.Id,
                    resource =>
                        resource.Enrichment!.Error!,
                    StringComparer.OrdinalIgnoreCase);

        return new EnrichmentStats
        {
            TotalResources =
                resources.Count,

            Successful =
                successful,

            Failed =
                failed,

            NotProcessed =
                notProcessed,

            SuccessRate =
                successRate,

            ApiVersions =
                apiVersions,

            Errors =
                errors
        };
    }

    private static void PrintScanDiagnostics(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyList<MetricProfile> metricProfiles,
        AzureResourceGraph resourceGraph,
        ScanResult result,
        TimeSpan duration)
    {
        Debug.WriteLine(
            "=== CLOUDLENS ASSESSMENT ===");

        Debug.WriteLine(
            $"Resources: {resources.Count}");

        Debug.WriteLine(
            $"Enrichment successful: " +
            $"{result.Enrichment.Successful}/" +
            $"{result.Enrichment.TotalResources}");

        Debug.WriteLine(
            $"Enrichment failed: " +
            $"{result.Enrichment.Failed}");

        Debug.WriteLine(
            $"Enrichment not processed: " +
            $"{result.Enrichment.NotProcessed}");

        Debug.WriteLine(
            $"Enrichment success rate: " +
            $"{result.Enrichment.SuccessRate:F1}%");

        if (result.Enrichment.ApiVersions.Count > 0)
        {
            Debug.WriteLine(
                "API versions:");

            foreach (var version in
                     result.Enrichment.ApiVersions
                         .OrderByDescending(
                             item => item.Value))
            {
                Debug.WriteLine(
                    $"  {version.Key}: " +
                    $"{version.Value}");
            }
        }

        if (result.Enrichment.Errors.Count > 0)
        {
            Debug.WriteLine(
                "Enrichment errors:");

            foreach (var error in
                     result.Enrichment.Errors)
            {
                Debug.WriteLine(
                    $"  {error.Key}: " +
                    $"{error.Value}");
            }
        }

        Debug.WriteLine(
            $"Relationships: " +
            $"{resources.Sum(
                resource =>
                    resource.Relationships.Count)}");

        Debug.WriteLine(
            $"Metric profiles: " +
            $"{metricProfiles.Count}");

        Debug.WriteLine(
            $"Findings: " +
            $"{result.Findings.Count}");

        Debug.WriteLine(
            $"Duration: " +
            $"{duration.TotalSeconds:F1}s");

        Debug.WriteLine(
            "=== END CLOUDLENS ASSESSMENT ===");
    }
}