using CloudLens.Core.Analysis;
using SeverityType = CloudLens.Core.Severity;
using CategoryType = CloudLens.Core.Category;

namespace CloudLens.Core;

public sealed class AssessmentInsights
{
    public IReadOnlyList<AssessmentSeveritySummary> Severity { get; init; } = [];

    public IReadOnlyList<AssessmentCategorySummary> Categories { get; init; } = [];

    public IReadOnlyList<AssessmentRiskItem> TopRisks { get; init; } = [];

    public IReadOnlyList<AssessmentRemediationSummary> Remediation { get; init; } = [];

    public AssessmentCoverageSummary Coverage { get; init; } = new();

    public int TotalFindings =>
        Severity.Sum(x => x.Count);

    public int TotalRemediations =>
        Remediation.Sum(x => x.Count);

    public static AssessmentInsights Build(
        TenantScanResult assessment)
    {
        if (assessment == null)
        {
            throw new ArgumentNullException(
                nameof(assessment));
        }

        var findings =
            assessment.AllFindings
                .ToList();

        var remediationActions =
            assessment.Subscriptions
                .SelectMany(
                    x => x.Result.Remediation.Actions)
                .ToList();

        var severity =
            Enum.GetValues<SeverityType>()
                .Select(
                    value =>
                        new AssessmentSeveritySummary(
                            value,
                            findings.Count(
                                finding =>
                                    finding.Severity == value)))
                .ToList();

        var categories =
            Enum.GetValues<CategoryType>()
                .Select(
                    category =>
                    {
                        var categoryFindings =
                            findings
                                .Where(
                                    finding =>
                                        finding.Category == category)
                                .ToList();

                        var score =
                            assessment.ScoresByCategory.TryGetValue(
                                category,
                                out var categoryScore)
                                ? categoryScore
                                : 100;

                        return new AssessmentCategorySummary(
                            category,
                            score,
                            categoryFindings.Count,
                            categoryFindings.Count(
                                x =>
                                    x.Severity ==
                                    SeverityType.Critical),
                            categoryFindings.Count(
                                x =>
                                    x.Severity ==
                                    SeverityType.High),
                            categoryFindings.Count(
                                x =>
                                    x.Severity ==
                                    SeverityType.Medium),
                            categoryFindings.Count(
                                x =>
                                    x.Severity ==
                                    SeverityType.Low));
                    })
                .OrderByDescending(
                    x => x.FindingCount)
                .ThenBy(
                    x => x.Score)
                .ToList();

        var topRisks =
            findings
                .OrderBy(
                    x =>
                        SeverityOrder(
                            x.Severity))
                .ThenByDescending(
                    x => x.MonthlySavingEur)
                .ThenBy(
                    x => x.Category)
                .Take(10)
                .Select(
                    finding =>
                        new AssessmentRiskItem(
                            finding.Id,
                            finding.RuleId,
                            finding.Title,
                            finding.Category,
                            finding.Severity,
                            finding.ResourceName,
                            finding.ResourceType,
                            finding.ResourceId,
                            finding.Impact,
                            finding.Recommendation,
                            finding.MonthlySavingEur))
                .ToList();

        var remediation =
            Enum.GetValues<RemediationStatus>()
                .Select(
                    status =>
                        new AssessmentRemediationSummary(
                            status,
                            remediationActions.Count(
                                x =>
                                    x.Status == status),
                            remediationActions.Count(
                                x =>
                                    x.Status == status &&
                                    x.Severity ==
                                    SeverityType.Critical),
                            remediationActions.Count(
                                x =>
                                    x.Status == status &&
                                    x.Severity ==
                                    SeverityType.High)))
                .ToList();

        var coverage =
            new AssessmentCoverageSummary
            {
                TotalResources =
                    assessment.Coverage.TotalResources,

                EnrichedResources =
                    assessment.Coverage.EnrichedResources,

                EnrichmentCoveragePercent =
                    assessment.Coverage
                        .ResourceEnrichmentCoveragePercent,

                TotalResourceTypes =
                    assessment.Coverage.TotalResourceTypes,

                SupportedResourceTypes =
                    assessment.Coverage.SupportedResourceTypes,

                GenericResourceTypes =
                    assessment.Coverage.GenericResourceTypes,

                UnsupportedResourceTypes =
                    assessment.Coverage.UnsupportedResourceTypes,

                ResourceTypeCoveragePercent =
                    assessment.Coverage.ResourceTypeCoveragePercent,

                SpecializedAnalyzerCoveragePercent =
                    assessment.Coverage
                        .SpecializedAnalyzerCoveragePercent,

                MetricCapableResources =
                    assessment.Coverage
                        .MetricCapableResources,

                MetricProfiles =
                    assessment.Coverage
                        .MetricProfiles
            };

        return new AssessmentInsights
        {
            Severity = severity,
            Categories = categories,
            TopRisks = topRisks,
            Remediation = remediation,
            Coverage = coverage
        };
    }

    private static int SeverityOrder(
        SeverityType severity)
    {
        return severity switch
        {
            SeverityType.Critical => 0,
            SeverityType.High => 1,
            SeverityType.Medium => 2,
            SeverityType.Low => 3,
            _ => 4
        };
    }
}

public sealed record AssessmentSeveritySummary(
    SeverityType Severity,
    int Count);

public sealed record AssessmentCategorySummary(
    CategoryType Category,
    int Score,
    int FindingCount,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount);

public sealed record AssessmentRiskItem(
    string FindingId,
    string RuleId,
    string Title,
    CategoryType Category,
    SeverityType Severity,
    string ResourceName,
    string ResourceType,
    string? ResourceId,
    string Impact,
    string Recommendation,
    double MonthlySavingEur);

public sealed record AssessmentRemediationSummary(
    RemediationStatus Status,
    int Count,
    int CriticalCount,
    int HighCount);

public sealed class AssessmentCoverageSummary
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
