using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class AssessmentContext
{
    public IReadOnlyList<AzureResource> Resources { get; }

    public AzureSubscription Subscription { get; }

    public AzureResourceGraph ResourceGraph { get; }

    public IReadOnlyList<MetricProfile> MetricProfiles { get; }

    public AssessmentContext(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        AzureResourceGraph resourceGraph,
        IReadOnlyList<MetricProfile>? metricProfiles = null)
    {
        Resources =
            resources ??
            throw new ArgumentNullException(
                nameof(resources));

        Subscription =
            subscription ??
            throw new ArgumentNullException(
                nameof(subscription));

        ResourceGraph =
            resourceGraph ??
            throw new ArgumentNullException(
                nameof(resourceGraph));

        MetricProfiles =
            metricProfiles ??
            Array.Empty<MetricProfile>();
    }
}