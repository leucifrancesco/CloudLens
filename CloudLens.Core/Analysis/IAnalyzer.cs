using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public interface IAnalyzer
{
    IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription);
}