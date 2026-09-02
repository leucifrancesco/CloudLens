using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ArchitectureAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings =
            new List<Finding>();

        AnalyzeVmPublicIpArchitecture(
            resources,
            findings);

        AnalyzeStorageReplication(
            resources,
            findings);

        AnalyzeBasicResourceDistribution(
            resources,
            subscription,
            findings);

        return findings;
    }

    // =========================================================
    // VM PUBLIC IP
    // =========================================================

    private static void AnalyzeVmPublicIpArchitecture(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var vms =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Compute/virtualMachines"));

        foreach (var vm in vms)
        {
            if (vm.Properties is not JsonElement properties)
            {
                continue;
            }

            if (!properties.TryGetProperty(
                    "networkProfile",
                    out var networkProfile))
            {
                continue;
            }

            if (!networkProfile.TryGetProperty(
                    "networkInterfaces",
                    out var interfaces) ||
                interfaces.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var nic in interfaces.EnumerateArray())
            {
                if (!nic.TryGetProperty(
                        "id",
                        out var nicIdElement) ||
                    nicIdElement.ValueKind !=
                    JsonValueKind.String)
                {
                    continue;
                }

                var nicId =
                    nicIdElement.GetString();

                if (string.IsNullOrWhiteSpace(nicId))
                {
                    continue;
                }

                // La NIC viene verificata contro il modello
                // normalizzato delle risorse scoperte.
                var hasNic =
                    resources.Any(
                        r =>
                            string.Equals(
                                r.Id,
                                nicId,
                                StringComparison.OrdinalIgnoreCase));

                if (!hasNic)
                {
                    continue;
                }
            }
        }
    }

    // =========================================================
    // STORAGE REPLICATION
    // =========================================================

    private static void AnalyzeStorageReplication(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var storageAccounts =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Storage/storageAccounts"));

        foreach (var storage in storageAccounts)
        {
            if (storage.Sku is not JsonElement sku)
            {
                continue;
            }

            if (!sku.TryGetProperty(
                    "name",
                    out var skuNameElement) ||
                skuNameElement.ValueKind !=
                JsonValueKind.String)
            {
                continue;
            }

            var skuName =
                skuNameElement.GetString();

            if (string.IsNullOrWhiteSpace(skuName))
            {
                continue;
            }

            if (skuName.Contains(
                    "LRS",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Reliability,

                        Severity:
                            Severity.Low,

                        RuleId:
                            "ST-LRS-REPLICATION",

                        Title:
                            "Storage Account con replica LRS",

                        Description:
                            $"Lo storage account '{storage.Name}' " +
                            "utilizza una replica LRS.",

                        Impact:
                            "LRS offre una resilienza inferiore rispetto " +
                            "a configurazioni con ridondanza geografica " +
                            "o zonale.",

                        Recommendation:
                            "Valutare ZRS, GRS o GZRS in funzione dei " +
                            "requisiti di disponibilità e disaster recovery.",

                        ResourceName:
                            storage.Name,

                        ResourceType:
                            storage.Type));
            }
        }
    }

    // =========================================================
    // BASIC ARCHITECTURE
    // =========================================================

    private static void AnalyzeBasicResourceDistribution(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var locations =
            resources
                .Select(
                    r => r.Location)
                .Where(
                    x => !string.IsNullOrWhiteSpace(x))
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        if (resources.Count == 0)
        {
            return;
        }

        if (locations.Count == 1)
        {
            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "ARCH-SINGLE-REGION",

                    Title:
                        "Ambiente distribuito in una sola region",

                    Description:
                        $"Le risorse analizzate risultano concentrate " +
                        $"nella region '{locations[0]}'.",

                    Impact:
                        "Un singolo failure domain geografico può " +
                        "aumentare il rischio di indisponibilità.",

                    Recommendation:
                        "Valutare una strategia multi-region quando " +
                        "i requisiti applicativi lo rendono necessario.",

                    ResourceName:
                        subscription.Name,

                    ResourceType:
                        "Microsoft.Resources/subscriptions"));
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static bool TypeEquals(
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }
}