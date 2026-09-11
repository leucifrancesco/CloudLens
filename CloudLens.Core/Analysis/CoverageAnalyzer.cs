using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CoverageAnalyzer
{
    private readonly ResourceTypeRegistry _registry;

    public CoverageAnalyzer(
        ResourceTypeRegistry? registry = null)
    {
        _registry =
            registry ??
            new ResourceTypeRegistry();
    }

    public CoverageReport Analyze(
        IReadOnlyList<AzureResource> resources,
        IReadOnlyList<MetricProfile> metricProfiles)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(
                nameof(resources));
        }

        if (metricProfiles == null)
        {
            throw new ArgumentNullException(
                nameof(metricProfiles));
        }

        if (resources.Count == 0)
        {
            return new CoverageReport();
        }

        var metricResourceIds =
            metricProfiles
                .Select(x => x.ResourceId)
                .Where(
                    x => !string.IsNullOrWhiteSpace(x))
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        var resourceTypeGroups =
            resources
                .GroupBy(
                    x => x.Type,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        var resourceTypeCoverage =
            new List<ResourceTypeCoverage>();

        foreach (var group in resourceTypeGroups)
        {
            var definition =
                _registry.Resolve(group.Key);

            var enriched =
                group.Count(
                    resource =>
                        resource.Enrichment?.Success == true);

            var metricCapable =
                group.Count(
                    resource =>
                        metricResourceIds.Contains(
                            resource.Id));

            var metricCount =
                metricProfiles.Count(
                    metric =>
                        group.Any(
                            resource =>
                                string.Equals(
                                    resource.Id,
                                    metric.ResourceId,
                                    StringComparison.OrdinalIgnoreCase)));

            CoverageStatus status;

            if (definition.SpecializedAnalyzer)
            {
                status =
                    enriched > 0
                        ? CoverageStatus.Supported
                        : CoverageStatus.NoData;
            }
            else if (enriched > 0)
            {
                status = CoverageStatus.Generic;
            }
            else
            {
                status = CoverageStatus.Unsupported;
            }

            resourceTypeCoverage.Add(
                new ResourceTypeCoverage(
                    ResourceType:
                        group.Key,

                    ServiceFamily:
                        definition.ServiceFamily,

                    ResourceCount:
                        group.Count(),

                    EnrichedResources:
                        enriched,

                    MetricCapableResources:
                        metricCapable,

                    MetricProfiles:
                        metricCount,

                    SpecializedAnalyzer:
                        definition.SpecializedAnalyzer,

                    Status:
                        status,

                    CoverageDescription:
                        definition.Description));
        }

        var serviceCoverage =
            resourceTypeCoverage
                .GroupBy(
                    x => x.ServiceFamily,
                    StringComparer.OrdinalIgnoreCase)
                .Select(
                    group =>
                    {
                        var resourceCount =
                            group.Sum(
                                x => x.ResourceCount);

                        var resourceTypes =
                            group.Count();

                        var enriched =
                            group.Sum(
                                x => x.EnrichedResources);

                        var metrics =
                            group.Sum(
                                x => x.MetricProfiles);

                        var specialized =
                            group.Any(
                                x => x.SpecializedAnalyzer);

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
                                    : group.Any(
                                        x =>
                                            x.Status ==
                                            CoverageStatus.NoData)
                                        ? CoverageStatus.NoData
                                        : CoverageStatus.Unsupported;

                        return new ServiceCoverage(
                            ServiceFamily:
                                group.Key,

                            ResourceCount:
                                resourceCount,

                            ResourceTypes:
                                resourceTypes,

                            EnrichedResources:
                                enriched,

                            MetricProfiles:
                                metrics,

                            SpecializedAnalyzer:
                                specialized,

                            Status:
                                status);
                    })
                .OrderBy(
                    x => x.ServiceFamily,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        var totalTypes =
            resourceTypeCoverage.Count;

        var supportedTypes =
            resourceTypeCoverage.Count(
                x =>
                    x.Status ==
                    CoverageStatus.Supported);

        var genericTypes =
            resourceTypeCoverage.Count(
                x =>
                    x.Status ==
                    CoverageStatus.Generic);

        var unsupportedTypes =
            resourceTypeCoverage.Count(
                x =>
                    x.Status ==
                    CoverageStatus.Unsupported);

        var enrichedResources =
            resources.Count(
                x =>
                    x.Enrichment?.Success == true);

        var metricCapableResources =
            metricResourceIds.Count(
                resourceId =>
                    resources.Any(
                        resource =>
                            string.Equals(
                                resource.Id,
                                resourceId,
                                StringComparison.OrdinalIgnoreCase)));

        return new CoverageReport
        {
            TotalResources =
                resources.Count,

            TotalResourceTypes =
                totalTypes,

            SupportedResourceTypes =
                supportedTypes,

            GenericResourceTypes =
                genericTypes,

            UnsupportedResourceTypes =
                unsupportedTypes,

            EnrichedResources =
                enrichedResources,

            MetricCapableResources =
                metricCapableResources,

            MetricProfiles =
                metricProfiles.Count,

            ResourceEnrichmentCoveragePercent =
                resources.Count == 0
                    ? 0
                    : enrichedResources * 100.0 /
                      resources.Count,

            ResourceTypeCoveragePercent =
                totalTypes == 0
                    ? 0
                    : (supportedTypes + genericTypes) *
                      100.0 /
                      totalTypes,

            SpecializedAnalyzerCoveragePercent =
                totalTypes == 0
                    ? 0
                    : supportedTypes * 100.0 /
                      totalTypes,

            ResourceTypes =
                resourceTypeCoverage
                    .OrderByDescending(
                        x => x.ResourceCount)
                    .ThenBy(
                        x => x.ResourceType,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList(),

            Services =
                serviceCoverage
        };
    }
}