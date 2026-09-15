using CloudLens.Core.Analysis;
namespace CloudLens.Core;

public sealed class AssessmentExportDocument
{
    public string ExportVersion { get; init; } = "1.0";

    public DateTimeOffset ExportedAt { get; init; }

    public string TenantId { get; init; } = "";

    public DateTimeOffset StartedAt { get; init; }

    public DateTimeOffset CompletedAt { get; init; }

    public int OverallScore { get; init; }

    public int TotalResources { get; init; }

    public int TotalResourceTypes { get; init; }

    public int TotalRelationships { get; init; }

    public int EnrichedResources { get; init; }

    public double EnrichmentCoveragePercent { get; init; }

    public int TotalMetricProfiles { get; init; }

    public int CriticalFindings { get; init; }

    public int HighFindings { get; init; }

    public int MediumFindings { get; init; }

    public int LowFindings { get; init; }

    public IReadOnlyList<AssessmentExportSubscription>
        Subscriptions { get; init; } = [];

    public IReadOnlyList<AssessmentExportResourceType>
        ResourceInventory { get; init; } = [];

    public IReadOnlyList<AssessmentExportFinding>
        Findings { get; init; } = [];

    public IReadOnlyList<AssessmentExportRemediation>
        Remediations { get; init; } = [];

    public IReadOnlyList<AssessmentExportMetric>
        Metrics { get; init; } = [];

    public IReadOnlyDictionary<Category, int>
        ScoresByCategory { get; init; } =
            new Dictionary<Category, int>();
}

public sealed record AssessmentExportSubscription(
    string Name,
    string Id,
    int Score,
    int Resources,
    int ResourceTypes,
    int Findings,
    int Remediations);

public sealed record AssessmentExportResourceType(
    string ResourceType,
    int Count);

public sealed record AssessmentExportFinding(
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
    double MonthlySavingEur,
    string? ResourceId,
    string? AzureCli);

public sealed record AssessmentExportRemediation(
    string Id,
    string FindingId,
    string RuleId,
    Category Category,
    Severity Severity,
    string Title,
    string Description,
    string ResourceName,
    string ResourceType,
    string? ResourceId,
    RemediationActionType ActionType,
    RemediationStatus Status,
    string Action,
    string? Command,
    bool RequiresReview);

public sealed record AssessmentExportMetric(
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