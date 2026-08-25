using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ArchitectureAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription)
    {
        // I controlli architetturali verranno aggiunti
        // nelle prossime fasi di sviluppo.

        return [];
    }
}