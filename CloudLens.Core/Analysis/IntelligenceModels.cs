using CloudLens.Core;

namespace CloudLens.Core.Analysis;

public enum AssessmentPriority
{
    P0 = 0,
    P1 = 1,
    P2 = 2,
    P3 = 3
}

public enum IntelligenceClassification
{
    CriticalRisk,
    HighPriority,
    QuickWin,
    Optimization,
    SystemicRisk
}

public sealed record IntelligenceRisk(
    string FindingId,
    string RuleId,
    string Title,
    string ResourceName,
    string ResourceType,
    string? ResourceId,
    Category Category,
    Severity Severity,
    AssessmentPriority Priority,
    IntelligenceClassification Classification,
    int PriorityScore,
    int ImpactScore,
    int EffortScore,
    bool IsQuickWin,
    bool IsSystemic,
    double MonthlySavingEur,
    string Rationale);

public sealed record SystemicRisk(
    string Id,
    string Title,
    Category Category,
    Severity Severity,
    int FindingCount,
    int AffectedResources,
    AssessmentPriority Priority,
    int PriorityScore,
    string Description,
    IReadOnlyList<string> FindingIds);

public sealed record RemediationRoadmapItem(
    string FindingId,
    string Title,
    Category Category,
    Severity Severity,
    AssessmentPriority Priority,
    IntelligenceClassification Classification,
    int PriorityScore,
    int ImpactScore,
    int EffortScore,
    double MonthlySavingEur,
    string Action,
    string? Command,
    bool RequiresReview);

public sealed class AssessmentIntelligence
{
    public IReadOnlyList<IntelligenceRisk> Risks { get; init; } = [];

    public IReadOnlyList<IntelligenceRisk> QuickWins { get; init; } = [];

    public IReadOnlyList<SystemicRisk> SystemicRisks { get; init; } = [];

    public IReadOnlyList<RemediationRoadmapItem> Roadmap { get; init; } = [];

    public int TotalRisks =>
        Risks.Count;

    public int QuickWinCount =>
        QuickWins.Count;

    public int SystemicRiskCount =>
        SystemicRisks.Count;

    public int P0Count =>
        Risks.Count(
            x => x.Priority == AssessmentPriority.P0);

    public int P1Count =>
        Risks.Count(
            x => x.Priority == AssessmentPriority.P1);

    public int P2Count =>
        Risks.Count(
            x => x.Priority == AssessmentPriority.P2);

    public int P3Count =>
        Risks.Count(
            x => x.Priority == AssessmentPriority.P3);

    public double PotentialMonthlySavingEur =>
        Risks.Sum(
            x => x.MonthlySavingEur);
}