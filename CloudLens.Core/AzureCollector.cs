using CloudLens.Core;
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
                new ArchitectureAnalyzer(),
                new CorrelationAnalyzer()
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
        if (subscription == null)
        {
            throw new ArgumentNullException(
                nameof(subscription));
        }

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

        // -----------------------------------------------------
        // RESOURCE DISCOVERY
        // -----------------------------------------------------

        var client =
            new AzureResourceClient(
                _http,
                token);

        var resources =
            await client.GetAzureResourcesAsync(
                subscription.Id,
                cancellationToken);

        // -----------------------------------------------------
        // ARM RESOURCE ENRICHMENT
        // -----------------------------------------------------

        var enricher =
            new AzureResourceEnricher(
                _http,
                token);

        await enricher.EnrichAsync(
            resources,
            cancellationToken);

        // -----------------------------------------------------
        // RESOURCE RELATIONSHIPS
        // -----------------------------------------------------

        var relationshipBuilder =
            new AzureRelationshipBuilder();

        relationshipBuilder.Build(
            resources);

        // -----------------------------------------------------
        // RESOURCE GRAPH
        // -----------------------------------------------------

        var resourceGraph =
            new AzureResourceGraph(
                resources);

        // -----------------------------------------------------
        // METRIC COLLECTION
        // -----------------------------------------------------

        var monitorClient =
            new AzureMonitorClient(
                _http,
                token);

        var rawResources =
            resources
                .Select(
                    resource => resource.Raw)
                .ToList();

        var metricProfiles =
            await monitorClient.GetMetricsAsync(
                rawResources,
                cancellationToken);

        // -----------------------------------------------------
        // ANALYSIS
        // -----------------------------------------------------

        var result =
            _assessmentEngine.Analyze(
                resources,
                subscription,
                metricProfiles);

        // -----------------------------------------------------
        // DIAGNOSTICS
        // -----------------------------------------------------

        PrintScanDiagnostics(
            resources,
            metricProfiles,
            resourceGraph);

        return result;
    }

    // =========================================================
    // DIAGNOSTICS
    // =========================================================

    private static void PrintScanDiagnostics(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyList<MetricProfile> metricProfiles,
        AzureResourceGraph resourceGraph)
    {
        Console.WriteLine();

        Console.WriteLine(
            "=========================================================");

        Console.WriteLine(
            "CLOUDLENS - AZURE DISCOVERY");

        Console.WriteLine(
            "=========================================================");

        // -----------------------------------------------------
        // GENERAL
        // -----------------------------------------------------

        Console.WriteLine(
            $"Risorse scoperte : {resources.Count}");

        Console.WriteLine(
            $"Metriche raccolte: {metricProfiles.Count}");

        Console.WriteLine();

        // -----------------------------------------------------
        // ARM ENRICHMENT
        // -----------------------------------------------------

        var enrichedCount =
            resources.Count(
                resource =>
                    resource.Enrichment?.Success == true);

        Console.WriteLine(
            "ARM ENRICHMENT:");

        Console.WriteLine();

        Console.WriteLine(
            $"Risorse arricchite: {enrichedCount}");

        Console.WriteLine(
            $"Risorse non arricchite: " +
            $"{resources.Count - enrichedCount}");

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
                    resource =>
                        resource.Type,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    group =>
                        group.Count())
                .ThenBy(
                    group =>
                        group.Key,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        foreach (var group in resourceGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");
        }

        Console.WriteLine();

        // -----------------------------------------------------
        // RESOURCE PAYLOAD DIAGNOSTICS
        // -----------------------------------------------------

        Console.WriteLine(
            "RESOURCE DETAILS:");

        Console.WriteLine();

        foreach (var group in resourceGroups)
        {
            Console.WriteLine(
                $"--- {group.Key} ({group.Count()}) ---");

            foreach (var resource in
                     group.Take(5))
            {
                Console.WriteLine(
                    $"Name: {resource.Name}");

                Console.WriteLine(
                    $"Id: {resource.Id}");

                Console.WriteLine(
                    $"Location: {resource.Location}");

                Console.WriteLine(
                    $"Resource Group: {resource.ResourceGroup}");

                Console.WriteLine(
                    $"Enrichment: " +
                    $"{resource.Enrichment?.Success == true}");

                Console.WriteLine(
                    "Raw:");

                Console.WriteLine(
                    resource.Raw.GetRawText());

                Console.WriteLine();
            }
        }

        // -----------------------------------------------------
        // RELATIONSHIPS
        // -----------------------------------------------------

        Console.WriteLine(
            "RESOURCE RELATIONSHIPS:");

        Console.WriteLine();

        var relationshipGroups =
            resources
                .SelectMany(
                    resource =>
                        resource.Relationships)
                .GroupBy(
                    relationship =>
                        relationship.RelationshipType,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    group =>
                        group.Count())
                .ThenBy(
                    group =>
                        group.Key,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        var totalRelationships =
            0;

        foreach (var group in relationshipGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");

            totalRelationships +=
                group.Count();
        }

        Console.WriteLine();

        Console.WriteLine(
            $"Relazioni totali: {totalRelationships}");

        // -----------------------------------------------------
        // RESOURCE GRAPH
        // -----------------------------------------------------

        var vmCount =
            resourceGraph
                .GetResources(
                    "Microsoft.Compute/virtualMachines")
                .Count;

        var nicCount =
            resourceGraph
                .GetResources(
                    "Microsoft.Network/networkInterfaces")
                .Count;

        Console.WriteLine();

        Console.WriteLine(
            "RESOURCE GRAPH:");

        Console.WriteLine();

        Console.WriteLine(
            $"VM nel graph : {vmCount}");

        Console.WriteLine(
            $"NIC nel graph: {nicCount}");

        // -----------------------------------------------------
        // METRICS BY RESOURCE TYPE
        // -----------------------------------------------------

        Console.WriteLine();

        Console.WriteLine(
            "METRICHE PER RESOURCE TYPE:");

        Console.WriteLine();

        var metricGroups =
            metricProfiles
                .GroupBy(
                    metric =>
                        metric.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    group =>
                        group.Count())
                .ThenBy(
                    group =>
                        group.Key,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        foreach (var group in metricGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");
        }

        // -----------------------------------------------------
        // UNIQUE METRIC TYPES
        // -----------------------------------------------------

        Console.WriteLine();

        Console.WriteLine(
            "METRICHE UNICHE:");

        Console.WriteLine();

        var metricNames =
            metricProfiles
                .GroupBy(
                    metric =>
                        $"{metric.ResourceType}|{metric.MetricName}",
                    StringComparer.OrdinalIgnoreCase)
                .Select(
                    group =>
                        group.First())
                .OrderBy(
                    metric =>
                        metric.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    metric =>
                        metric.MetricName,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        foreach (var metric in
                 metricNames.Take(100))
        {
            Console.WriteLine(
                $"{metric.ResourceType} | " +
                $"{metric.MetricName} | " +
                $"{metric.Unit}");
        }

        // -----------------------------------------------------
        // FIRST 20 METRIC PROFILES
        // -----------------------------------------------------

        Console.WriteLine();

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