using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public interface IAnalyzer
{
    IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription);
}