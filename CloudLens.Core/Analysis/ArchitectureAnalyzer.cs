using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ArchitectureAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        // Per ora non vengono generati finding architetturali
        // basati esclusivamente su configurazioni che possono essere
        // perfettamente valide in determinati scenari.
        //
        // Esempi:
        // - LRS non è automaticamente una configurazione errata.
        // - Una singola region non implica automaticamente un problema
        //   di resilienza.
        //
        // I futuri controlli architetturali dovranno essere basati
        // sulla topologia effettiva e, quando necessario, su requisiti
        // espliciti di disponibilità/DR.

        return [];
    }
}