namespace CloudLens.Core.Analysis;

public enum CoverageStatus
{
    Supported,
    Generic,
    NoData,
    Unsupported,
    Error
}

public sealed record ResourceTypeCoverage(
    string ResourceType,
    string ServiceFamily,
    int ResourceCount,
    int EnrichedResources,
    int MetricCapableResources,
    int MetricProfiles,
    bool SpecializedAnalyzer,
    CoverageStatus Status,
    string CoverageDescription);

public sealed record ServiceCoverage(
    string ServiceFamily,
    int ResourceCount,
    int ResourceTypes,
    int EnrichedResources,
    int MetricProfiles,
    bool SpecializedAnalyzer,
    CoverageStatus Status);

public sealed class CoverageReport
{
    public int TotalResources { get; init; }

    public int TotalResourceTypes { get; init; }

    public int SupportedResourceTypes { get; init; }

    public int GenericResourceTypes { get; init; }

    public int UnsupportedResourceTypes { get; init; }

    public int EnrichedResources { get; init; }

    public int MetricCapableResources { get; init; }

    public int MetricProfiles { get; init; }

    public double ResourceEnrichmentCoveragePercent { get; init; }

    public double ResourceTypeCoveragePercent { get; init; }

    public double SpecializedAnalyzerCoveragePercent { get; init; }

    public IReadOnlyList<ResourceTypeCoverage> ResourceTypes { get; init; } = [];

    public IReadOnlyList<ServiceCoverage> Services { get; init; } = [];
}