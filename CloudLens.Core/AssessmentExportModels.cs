using CloudLens.Core.Analysis;

namespace CloudLens.Core;

public sealed class AssessmentExportDocument
{
    public string ExportVersion { get; init; } = "1.1";

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

    public AssessmentExportInsights Insights { get; init; } = new();

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

public sealed class AssessmentExportInsights
{
    public IReadOnlyList<AssessmentExportSeveritySummary>
        Severity { get; init; } = [];

    public IReadOnlyList<AssessmentExportCategorySummary>
        Categories { get; init; } = [];

    public IReadOnlyList<AssessmentExportRiskItem>
        TopRisks { get; init; } = [];

    public IReadOnlyList<AssessmentExportRemediationSummary>
        Remediation { get; init; } = [];

    public AssessmentExportCoverageSummary Coverage { get; init; } = new();
}

public sealed record AssessmentExportSeveritySummary(
    Severity Severity,
    int Count);

public sealed record AssessmentExportCategorySummary(
    Category Category,
    int Score,
    int FindingCount,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount);

public sealed record AssessmentExportRiskItem(
    string FindingId,
    string RuleId,
    string Title,
    Category Category,
    Severity Severity,
    string ResourceName,
    string ResourceType,
    string? ResourceId,
    string Impact,
    string Recommendation,
    double MonthlySavingEur);

public sealed record AssessmentExportRemediationSummary(
    RemediationStatus Status,
    int Count,
    int CriticalCount,
    int HighCount);

public sealed class AssessmentExportCoverageSummary
{
    public int TotalResources { get; init; }

    public int EnrichedResources { get; init; }

    public double EnrichmentCoveragePercent { get; init; }

    public int TotalResourceTypes { get; init; }

    public int SupportedResourceTypes { get; init; }

    public int GenericResourceTypes { get; init; }

    public int UnsupportedResourceTypes { get; init; }

    public double ResourceTypeCoveragePercent { get; init; }

    public double SpecializedAnalyzerCoveragePercent { get; init; }

    public int MetricCapableResources { get; init; }

    public int MetricProfiles { get; init; }
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