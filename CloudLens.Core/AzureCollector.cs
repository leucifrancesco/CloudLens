using CloudLens.Core;
using CloudLens.Core.Analysis;

namespace CloudLens.Core.Azure;

public sealed class AzureCollector
{
    private readonly HttpClient _http;
    private readonly AssessmentEngine _assessmentEngine;
    private readonly CoverageAnalyzer _coverageAnalyzer;
    private readonly RiskPrioritizer _riskPrioritizer;

    public AzureCollector(HttpClient http)
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

        _coverageAnalyzer =
            new CoverageAnalyzer();

        _riskPrioritizer =
            new RiskPrioritizer();
    }

    // =========================================================
    // INTERACTIVE AUTHENTICATION + SUBSCRIPTION DISCOVERY
    // =========================================================

    public async Task<List<AzureSubscription>>
        AuthenticateInteractiveAndListSubscriptionsAsync(
            string tenantId,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));
        }

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
    // INTERACTIVE SINGLE-SUBSCRIPTION ASSESSMENT
    // =========================================================

    public async Task<ScanResult>
        ScanInteractiveAsync(
            string token,
            AzureSubscription subscription,
            CancellationToken cancellationToken = default)
    {
        ValidateToken(token);
        ValidateSubscription(subscription);

        return await ScanWithTokenAsync(
            token,
            subscription,
            cancellationToken);
    }

    // =========================================================
    // INTERACTIVE TENANT SCAN
    // =========================================================

    public async Task<TenantScanResult>
        ScanTenantInteractiveAsync(
            string token,
            CancellationToken cancellationToken = default)
    {
        ValidateToken(token);

        var subscriptionClient =
            new AzureResourceClient(
                _http,
                token);

        var subscriptions =
            await subscriptionClient.GetSubscriptionsAsync(
                cancellationToken);

        return await ScanTenantWithTokenAsync(
            token,
            subscriptions,
            cancellationToken);
    }

    // =========================================================
    // INTERACTIVE TENANT SCAN
    // USING EXISTING TENANT + TOKEN + SUBSCRIPTIONS
    // =========================================================

    public async Task<TenantScanResult>
        ScanTenantInteractiveAsync(
            string tenantId,
            string token,
            IReadOnlyList<AzureSubscription> subscriptions,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));
        }

        ValidateToken(token);

        if (subscriptions == null)
        {
            throw new ArgumentNullException(
                nameof(subscriptions));
        }

        return await ScanTenantWithTokenAsync(
            token,
            subscriptions,
            cancellationToken,
            tenantId);
    }

    // =========================================================
    // TENANT SCAN USING AN EXISTING SUBSCRIPTION LIST
    // =========================================================

    public async Task<TenantScanResult>
        ScanTenantAsync(
            string token,
            IReadOnlyList<AzureSubscription> subscriptions,
            CancellationToken cancellationToken = default)
    {
        ValidateToken(token);

        if (subscriptions == null)
        {
            throw new ArgumentNullException(
                nameof(subscriptions));
        }

        return await ScanTenantWithTokenAsync(
            token,
            subscriptions,
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
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException(
                "Client ID obbligatorio.",
                nameof(clientId));
        }

        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ArgumentException(
                "Client secret obbligatorio.",
                nameof(clientSecret));
        }

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
    // SERVICE PRINCIPAL SINGLE-SUBSCRIPTION SCAN
    // =========================================================

    public async Task<ScanResult>
        ScanAsync(
            string tenantId,
            string clientId,
            string clientSecret,
            AzureSubscription subscription,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException(
                "Client ID obbligatorio.",
                nameof(clientId));
        }

        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ArgumentException(
                "Client secret obbligatorio.",
                nameof(clientSecret));
        }

        ValidateSubscription(subscription);

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
    // SERVICE PRINCIPAL TENANT SCAN
    // =========================================================

    public async Task<TenantScanResult>
        ScanTenantAsync(
            string tenantId,
            string clientId,
            string clientSecret,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException(
                "Tenant ID obbligatorio.",
                nameof(tenantId));
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException(
                "Client ID obbligatorio.",
                nameof(clientId));
        }

        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ArgumentException(
                "Client secret obbligatorio.",
                nameof(clientSecret));
        }

        var authenticator =
            new AzureAuthenticator(_http);

        var token =
            await authenticator.GetAccessTokenAsync(
                tenantId,
                clientId,
                clientSecret,
                cancellationToken);

        var subscriptionClient =
            new AzureResourceClient(
                _http,
                token);

        var subscriptions =
            await subscriptionClient.GetSubscriptionsAsync(
                cancellationToken);

        return await ScanTenantWithTokenAsync(
            token,
            subscriptions,
            cancellationToken,
            tenantId);
    }

    // =========================================================
    // TENANT SCAN
    // =========================================================

    private async Task<TenantScanResult>
        ScanTenantWithTokenAsync(
            string token,
            IReadOnlyList<AzureSubscription> subscriptions,
            CancellationToken cancellationToken,
            string? tenantId = null)
    {
        ValidateToken(token);

        if (subscriptions.Count == 0)
        {
            var now =
                DateTimeOffset.UtcNow;

            var emptyAssessment =
                new TenantScanResult
                {
                    TenantId =
                        tenantId ?? "",

                    StartedAt =
                        now,

                    CompletedAt =
                        now,

                    Subscriptions = []
                };

            emptyAssessment.Intelligence =
                _riskPrioritizer.Analyze(
                    emptyAssessment);

            return emptyAssessment;
        }

        var startedAt =
            DateTimeOffset.UtcNow;

        var assessments =
            new List<SubscriptionAssessment>();

        foreach (var subscription in subscriptions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                Console.WriteLine();
                Console.WriteLine(
                    $"CloudLens - scan subscription: " +
                    $"{subscription.Name} " +
                    $"({subscription.Id})");

                var assessment =
                    await ScanSubscriptionAsync(
                        token,
                        subscription,
                        cancellationToken);

                assessments.Add(
                    assessment);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"Errore durante la scansione della " +
                    $"subscription {subscription.Name}: " +
                    $"{ex.Message}");

                assessments.Add(
                    CreateFailedAssessment(
                        subscription,
                        ex));
            }
        }

        var tenantAssessment =
            new TenantScanResult
            {
                TenantId =
                    tenantId ?? "",

                StartedAt =
                    startedAt,

                CompletedAt =
                    DateTimeOffset.UtcNow,

                Subscriptions =
                    assessments
            };

        // =====================================================
        // PHASE 9 - ASSESSMENT INTELLIGENCE
        // =====================================================

        tenantAssessment.Intelligence =
            _riskPrioritizer.Analyze(
                tenantAssessment);

        Console.WriteLine();
        Console.WriteLine(
            "CLOUDLENS - ASSESSMENT INTELLIGENCE");
        Console.WriteLine(
            $"Risks: {tenantAssessment.Intelligence.TotalRisks}");
        Console.WriteLine(
            $"P0: {tenantAssessment.Intelligence.P0Count}");
        Console.WriteLine(
            $"P1: {tenantAssessment.Intelligence.P1Count}");
        Console.WriteLine(
            $"P2: {tenantAssessment.Intelligence.P2Count}");
        Console.WriteLine(
            $"P3: {tenantAssessment.Intelligence.P3Count}");
        Console.WriteLine(
            $"Quick Wins: {tenantAssessment.Intelligence.QuickWinCount}");
        Console.WriteLine(
            $"Systemic Risks: {tenantAssessment.Intelligence.SystemicRiskCount}");
        Console.WriteLine(
            $"Potential Monthly Saving: " +
            $"{tenantAssessment.Intelligence.PotentialMonthlySavingEur:F2} EUR");

        // =====================================================
        // PHASE 13 - ASSESSMENT QUALITY
        // =====================================================

        var quality =
            tenantAssessment.Quality;

        Console.WriteLine();
        Console.WriteLine(
            "CLOUDLENS - ASSESSMENT QUALITY");
        Console.WriteLine(
            $"Status: {quality.Status}");
        Console.WriteLine(
            $"Subscriptions: {quality.TotalSubscriptions}");
        Console.WriteLine(
            $"Complete: {quality.CompleteSubscriptions}");
        Console.WriteLine(
            $"Partial: {quality.PartialSubscriptions}");
        Console.WriteLine(
            $"Failed: {quality.FailedSubscriptions}");
        Console.WriteLine(
            $"Unsupported: {quality.UnsupportedSubscriptions}");
        Console.WriteLine(
            $"Enrichment Coverage: " +
            $"{quality.EnrichmentCoveragePercent:F2}%");
        Console.WriteLine(
            $"Metric Coverage: " +
            $"{quality.MetricCoveragePercent:F2}%");

        return tenantAssessment;
    }

    // =========================================================
    // SUBSCRIPTION SCAN
    // =========================================================

    private async Task<SubscriptionAssessment>
        ScanSubscriptionAsync(
            string token,
            AzureSubscription subscription,
            CancellationToken cancellationToken)
    {
        ValidateToken(token);
        ValidateSubscription(subscription);

        var qualityStatus =
            AssessmentQualityStatus.Complete;

        var errors =
            new List<string>();

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

        try
        {
            await enricher.EnrichAsync(
                resources,
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            qualityStatus =
                AssessmentQualityStatus.Partial;

            errors.Add(
                $"ARM enrichment failed: {ex.Message}");

            Console.WriteLine(
                $"ARM enrichment error for " +
                $"{subscription.Name}: {ex.Message}");
        }

        // -----------------------------------------------------
        // RESOURCE RELATIONSHIPS
        // -----------------------------------------------------

        var relationshipBuilder =
            new AzureRelationshipBuilder();

        try
        {
            relationshipBuilder.Build(
                resources);
        }
        catch (Exception ex)
        {
            qualityStatus =
                AssessmentQualityStatus.Partial;

            errors.Add(
                $"Relationship analysis failed: {ex.Message}");

            Console.WriteLine(
                $"Relationship analysis error for " +
                $"{subscription.Name}: {ex.Message}");
        }

        // -----------------------------------------------------
        // RESOURCE GRAPH
        // -----------------------------------------------------

        var resourceGraph =
            new AzureResourceGraph(
                resources);

        // -----------------------------------------------------
        // METRIC COLLECTION
        // -----------------------------------------------------

        var metricProfiles =
            new List<MetricProfile>();

        var monitorClient =
            new AzureMonitorClient(
                _http,
                token);

        var rawResources =
            resources
                .Select(resource => resource.Raw)
                .ToList();

        try
        {
            metricProfiles =
                await monitorClient.GetMetricsAsync(
                    rawResources,
                    cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            qualityStatus =
                AssessmentQualityStatus.Partial;

            errors.Add(
                $"Metric collection failed: {ex.Message}");

            Console.WriteLine(
                $"Metric collection error for " +
                $"{subscription.Name}: {ex.Message}");
        }

        // -----------------------------------------------------
        // ASSESSMENT
        // -----------------------------------------------------

        ScanResult result;

        try
        {
            result =
                _assessmentEngine.Analyze(
                    resources,
                    subscription,
                    metricProfiles);

            result.MetricProfiles =
                metricProfiles;
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"Assessment engine error for " +
                $"{subscription.Name}: {ex.Message}");

            return CreateFailedAssessment(
                subscription,
                ex,
                resources);
        }

        // -----------------------------------------------------
        // COVERAGE
        // -----------------------------------------------------

        try
        {
            result.Coverage =
                _coverageAnalyzer.Analyze(
                    resources,
                    metricProfiles);
        }
        catch (Exception ex)
        {
            qualityStatus =
                AssessmentQualityStatus.Partial;

            errors.Add(
                $"Coverage analysis failed: {ex.Message}");

            Console.WriteLine(
                $"Coverage analysis error for " +
                $"{subscription.Name}: {ex.Message}");
        }

        // -----------------------------------------------------
        // DIAGNOSTICS
        // -----------------------------------------------------

        try
        {
            PrintScanDiagnostics(
                resources,
                metricProfiles,
                resourceGraph);
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"Diagnostics error for " +
                $"{subscription.Name}: {ex.Message}");
        }

        var errorMessage =
            errors.Count == 0
                ? null
                : string.Join(
                    " | ",
                    errors);

        return new SubscriptionAssessment(
            subscription,
            result,
            resources)
        {
            Status =
                qualityStatus,

            ErrorMessage =
                errorMessage
        };
    }

    // =========================================================
    // COMMON SINGLE-SUBSCRIPTION TOKEN SCAN
    // =========================================================

    private async Task<ScanResult>
        ScanWithTokenAsync(
            string token,
            AzureSubscription subscription,
            CancellationToken cancellationToken)
    {
        var assessment =
            await ScanSubscriptionAsync(
                token,
                subscription,
                cancellationToken);

        return assessment.Result;
    }

    // =========================================================
    // FAILED SUBSCRIPTION ASSESSMENT
    // =========================================================

    private static SubscriptionAssessment
        CreateFailedAssessment(
            AzureSubscription subscription,
            Exception exception,
            IReadOnlyList<AzureResource>? resources = null)
    {
        var result =
            new ScanResult
            {
                SubscriptionName =
                    subscription.Name,

                SubscriptionId =
                    subscription.Id,

                Findings = [],

                MetricProfiles = []
            };

        return new SubscriptionAssessment(
            subscription,
            result,
            resources ?? [])
        {
            Status =
                AssessmentQualityStatus.Failed,

            ErrorMessage =
                exception.Message
        };
    }

    // =========================================================
    // VALIDATION
    // =========================================================

    private static void ValidateToken(
        string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException(
                "Access token obbligatorio.",
                nameof(token));
        }
    }

    private static void ValidateSubscription(
        AzureSubscription subscription)
    {
        if (subscription == null)
        {
            throw new ArgumentNullException(
                nameof(subscription));
        }

        if (string.IsNullOrWhiteSpace(subscription.Id))
        {
            throw new ArgumentException(
                "Subscription ID obbligatorio.",
                nameof(subscription));
        }
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

        Console.WriteLine(
            $"Risorse scoperte : {resources.Count}");

        Console.WriteLine(
            $"Metriche raccolte: {metricProfiles.Count}");

        Console.WriteLine();

        var enrichedCount =
            resources.Count(
                resource =>
                    resource.Enrichment?.Success == true);

        Console.WriteLine(
            "ARM ENRICHMENT:");

        Console.WriteLine(
            $"Risorse arricchite: {enrichedCount}");

        Console.WriteLine(
            $"Risorse non arricchite: " +
            $"{resources.Count - enrichedCount}");

        Console.WriteLine();

        Console.WriteLine(
            "RISORSE PER RESOURCE TYPE:");

        Console.WriteLine();

        var resourceGroups =
            resources
                .GroupBy(
                    resource => resource.Type,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    group => group.Count())
                .ThenBy(
                    group => group.Key,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        foreach (var group in resourceGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");
        }

        Console.WriteLine();

        Console.WriteLine(
            "RESOURCE DETAILS:");

        Console.WriteLine();

        foreach (var group in resourceGroups)
        {
            Console.WriteLine(
                $"--- {group.Key} ({group.Count()}) ---");

            foreach (var resource in group.Take(5))
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

        Console.WriteLine(
            "RESOURCE RELATIONSHIPS:");

        Console.WriteLine();

        var relationshipGroups =
            resources
                .SelectMany(
                    resource => resource.Relationships)
                .GroupBy(
                    relationship =>
                        relationship.RelationshipType,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    group => group.Count())
                .ThenBy(
                    group => group.Key,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        var totalRelationships = 0;

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

        Console.WriteLine();

        Console.WriteLine(
            "METRICHE PER RESOURCE TYPE:");

        Console.WriteLine();

        var metricGroups =
            metricProfiles
                .GroupBy(
                    metric => metric.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(
                    group => group.Count())
                .ThenBy(
                    group => group.Key,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        foreach (var group in metricGroups)
        {
            Console.WriteLine(
                $"{group.Key} -> {group.Count()}");
        }

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
                    group => group.First())
                .OrderBy(
                    metric => metric.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    metric => metric.MetricName,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        foreach (var metric in metricNames.Take(100))
        {
            Console.WriteLine(
                $"{metric.ResourceType} | " +
                $"{metric.MetricName} | " +
                $"{metric.Unit}");
        }

        Console.WriteLine();

        Console.WriteLine(
            "PRIME 20 METRICHE RACCOLTE:");

        Console.WriteLine();

        foreach (var metric in metricProfiles.Take(20))
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