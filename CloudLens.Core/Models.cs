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
    Operations
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
    public int Resources { get; init; } = 0;
    public int Vms { get; init; } = 0;
    public int Disks { get; init; } = 0;
    public int Nsgs { get; init; } = 0;
    public int PublicIps { get; init; } = 0;
    public int StorageAccounts { get; init; } = 0;
    public int Advisor { get; init; } = 0;
    public double MonthlyCostEur { get; init; } = 0;
}

public sealed class EnrichmentStats
{
    public int TotalResources { get; init; } = 0;
    public int Successful { get; init; } = 0;
    public int Failed { get; init; } = 0;
    public int NotProcessed { get; init; } = 0;
    public double SuccessRate { get; init; } = 0;

    public Dictionary<string, int> ApiVersions { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, string> Errors { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
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

    public EnrichmentStats Enrichment { get; set; } = new();

    public List<AzureResource> Resources { get; init; } = [];
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