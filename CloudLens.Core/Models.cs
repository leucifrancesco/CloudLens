using CloudLens.Core.Analysis;
using CloudLens.Core.Azure;

namespace CloudLens.Core;

public enum Severity
{
    Critical,
    High,
    Medium,
    Low
}

public enum Category
{
    Security,
    Cost,
    Reliability,
    Performance,
    Operations,
    Architecture,
    Governance
}

public sealed record Finding(
    string Id,
    Category Category,
    Severity Severity,
    string RuleId,
    string Title,
    string Description,
    string Impact,
    string Recommendation,
    string ResourceName,
    string ResourceType,
    double MonthlySavingEur = 0,
    string? AzureCli = null,
    string? ResourceId = null);

public sealed record MetricProfile(
    string ResourceId,
    string ResourceName,
    string ResourceType,
    string MetricName,
    string? MetricDisplayName,
    string? Unit,
    string? MetricNamespace,
    double Average,
    double Minimum,
    double Maximum,
    int SampleCount,
    int LookbackDays);

public sealed class ScanStats
{
    public int Resources { get; init; }

    public int Vms { get; init; }

    public int Disks { get; init; }

    public int Nsgs { get; init; }

    public int PublicIps { get; init; }

    public int StorageAccounts { get; init; }

    public int Advisor { get; init; }

    public double MonthlyCostEur { get; init; }

    public int ResourceTypes { get; init; }

    public int EnrichedResources { get; init; }

    public int Relationships { get; init; }

    public int MetricProfiles { get; init; }

    public double EnrichmentCoveragePercent =>
        Resources == 0
            ? 0
            : EnrichedResources * 100.0 / Resources;

    public double MetricsCoveragePercent =>
        Resources == 0
            ? 0
            : MetricProfiles > 0
                ? Math.Min(
                    100,
                    MetricProfiles * 100.0 / Resources)
                : 0;
}

public sealed class ScanResult
{
    public string SubscriptionName { get; init; } = "";
    public string SubscriptionId { get; init; } = "";

    public int Score { get; init; }

    public ScanStats Stats { get; init; } = new();

    public List<Finding> Findings { get; init; } = [];

    public Dictionary<Category, int> ScoresByCategory { get; init; } = [];

    public List<MetricProfile> MetricProfiles { get; set; } = [];

    public CoverageReport Coverage { get; set; } = new();

    public RemediationPlan Remediation { get; set; } = new();
}

public sealed class AzureMetricAggregate
{
    public string ResourceId { get; init; } = "";

    public string ResourceName { get; init; } = "";

    public string ResourceType { get; init; } = "";

    public string MetricName { get; init; } = "";

    public double Average { get; init; }

    public double Minimum { get; init; }

    public double Maximum { get; init; }

    public int Samples { get; init; }
}

public sealed record ResourceTypeSummary(
    string ResourceType,
    int Count);

public sealed record SubscriptionAssessment(
    AzureSubscription Subscription,
    ScanResult Result,
    IReadOnlyList<AzureResource> Resources);

public sealed class TenantScanResult
{
    public string TenantId { get; init; } = "";

    public DateTimeOffset StartedAt { get; init; }

    public DateTimeOffset CompletedAt { get; init; }

    public List<SubscriptionAssessment> Subscriptions { get; init; } = [];

    public IReadOnlyList<AzureResource> AllResources =>
        Subscriptions
            .SelectMany(x => x.Resources)
            .ToList();

    public IReadOnlyList<Finding> AllFindings =>
        Subscriptions
            .SelectMany(x => x.Result.Findings)
            .ToList();

    public IReadOnlyList<MetricProfile> AllMetricProfiles =>
        Subscriptions
            .SelectMany(x => x.Result.MetricProfiles)
            .ToList();

    public IReadOnlyList<ResourceTypeSummary> ResourceTypes =>
        AllResources
            .GroupBy(
                resource => resource.Type,
                StringComparer.OrdinalIgnoreCase)
            .Select(
                group =>
                    new ResourceTypeSummary(
                        group.Key,
                        group.Count()))
            .OrderByDescending(x => x.Count)
            .ThenBy(
                x => x.ResourceType,
                StringComparer.OrdinalIgnoreCase)
            .ToList();

    public int TotalResources =>
        AllResources.Count;

    public int TotalResourceTypes =>
        ResourceTypes.Count;

    public int TotalRelationships =>
        AllResources.Sum(
            resource =>
                resource.Relationships.Count);

    public int EnrichedResources =>
        AllResources.Count(
            resource =>
                resource.Enrichment?.Success == true);

    public double EnrichmentCoveragePercent =>
        TotalResources == 0
            ? 0
            : EnrichedResources * 100.0 /
              TotalResources;

    public int TotalMetricProfiles =>
        AllMetricProfiles.Count;

    public int CriticalFindings =>
        AllFindings.Count(
            finding =>
                finding.Severity ==
                Severity.Critical);

    public int HighFindings =>
        AllFindings.Count(
            finding =>
                finding.Severity ==
                Severity.High);

    public int MediumFindings =>
        AllFindings.Count(
            finding =>
                finding.Severity ==
                Severity.Medium);

    public int LowFindings =>
        AllFindings.Count(
            finding =>
                finding.Severity ==
                Severity.Low);

    public int OverallScore
    {
        get
        {
            if (Subscriptions.Count == 0)
            {
                return 100;
            }

            return (int)Math.Round(
                Subscriptions
                    .Select(x => x.Result.Score)
                    .Average());
        }
    }

    public Dictionary<Category, int> ScoresByCategory
    {
        get
        {
            var result =
                new Dictionary<Category, int>();

            foreach (var category in
                     Enum.GetValues<Category>())
            {
                var scores =
                    Subscriptions
                        .Where(
                            x =>
                                x.Result.ScoresByCategory
                                    .ContainsKey(category))
                        .Select(
                            x =>
                                x.Result.ScoresByCategory[
                                    category])
                        .ToList();

                result[category] =
                    scores.Count == 0
                        ? 100
                        : (int)Math.Round(
                            scores.Average());
            }

            return result;
        }
    }

    public CoverageReport Coverage
    {
        get
        {
            if (Subscriptions.Count == 0)
            {
                return new CoverageReport();
            }

            var allResourceTypes =
                Subscriptions
                    .SelectMany(
                        x =>
                            x.Result.Coverage.ResourceTypes)
                    .ToList();

            var allServices =
                Subscriptions
                    .SelectMany(
                        x =>
                            x.Result.Coverage.Services)
                    .GroupBy(
                        x => x.ServiceFamily,
                        StringComparer.OrdinalIgnoreCase)
                    .Select(
                        group =>
                        {
                            var resources =
                                group.Sum(
                                    x => x.ResourceCount);

                            var types =
                                group.Sum(
                                    x => x.ResourceTypes);

                            var enriched =
                                group.Sum(
                                    x => x.EnrichedResources);

                            var metrics =
                                group.Sum(
                                    x => x.MetricProfiles);

                            var specialized =
                                group.Any(
                                    x =>
                                        x.SpecializedAnalyzer);

                            var status =
                                group.Any(
                                    x =>
                                        x.Status ==
                                        CoverageStatus.Supported)
                                    ? CoverageStatus.Supported
                                    : group.Any(
                                        x =>
                                            x.Status ==
                                            CoverageStatus.Generic)
                                        ? CoverageStatus.Generic
                                        : CoverageStatus.Unsupported;

                            return new ServiceCoverage(
                                group.Key,
                                resources,
                                types,
                                enriched,
                                metrics,
                                specialized,
                                status);
                        })
                    .OrderBy(
                        x => x.ServiceFamily,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();

            var supported =
                allResourceTypes.Count(
                    x =>
                        x.Status ==
                        CoverageStatus.Supported);

            var generic =
                allResourceTypes.Count(
                    x =>
                        x.Status ==
                        CoverageStatus.Generic);

            var unsupported =
                allResourceTypes.Count(
                    x =>
                        x.Status ==
                        CoverageStatus.Unsupported);

            var total =
                TotalResources;

            var enriched =
                EnrichedResources;

            var metricProfiles =
                TotalMetricProfiles;

            var metricResourceIds =
                AllMetricProfiles
                    .Select(x => x.ResourceId)
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .Count();

            return new CoverageReport
            {
                TotalResources =
                    total,

                TotalResourceTypes =
                    allResourceTypes.Count,

                SupportedResourceTypes =
                    supported,

                GenericResourceTypes =
                    generic,

                UnsupportedResourceTypes =
                    unsupported,

                EnrichedResources =
                    enriched,

                MetricCapableResources =
                    metricResourceIds,

                MetricProfiles =
                    metricProfiles,

                ResourceEnrichmentCoveragePercent =
                    total == 0
                        ? 0
                        : enriched * 100.0 /
                          total,

                ResourceTypeCoveragePercent =
                    allResourceTypes.Count == 0
                        ? 0
                        : (supported + generic) *
                          100.0 /
                          allResourceTypes.Count,

                SpecializedAnalyzerCoveragePercent =
                    allResourceTypes.Count == 0
                        ? 0
                        : supported * 100.0 /
                          allResourceTypes.Count,

                ResourceTypes =
                    allResourceTypes
                        .OrderByDescending(
                            x => x.ResourceCount)
                        .ThenBy(
                            x => x.ResourceType,
                            StringComparer.OrdinalIgnoreCase)
                        .ToList(),

                Services =
                    allServices
            };
        }
    }
}