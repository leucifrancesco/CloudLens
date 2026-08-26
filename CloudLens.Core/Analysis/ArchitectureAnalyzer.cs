using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ArchitectureAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
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
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var vms =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Compute/virtualMachines"));

        foreach (var vm in vms)
        {
            if (!vm.TryGetProperty(
                    "properties",
                    out var properties))
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
                var nicId =
                    GetString(
                        nic,
                        "id");

                if (string.IsNullOrWhiteSpace(nicId))
                {
                    continue;
                }

                // Resource Graph contiene già le NIC come risorse
                // quando sono presenti nell'inventory.
                var hasNic =
                    resources.Any(
                        r =>
                            string.Equals(
                                GetString(r, "id"),
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
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var storageAccounts =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Storage/storageAccounts"));

        foreach (var storage in storageAccounts)
        {
            if (!storage.TryGetProperty(
                    "sku",
                    out var sku))
            {
                continue;
            }

            var skuName =
                GetString(
                    sku,
                    "name");

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
                            $"Lo storage account '{ResourceName(storage)}' " +
                            "utilizza una replica LRS.",

                        Impact:
                            "LRS offre una resilienza inferiore rispetto " +
                            "a configurazioni con ridondanza geografica " +
                            "o zonale.",

                        Recommendation:
                            "Valutare ZRS, GRS o GZRS in funzione dei " +
                            "requisiti di disponibilità e disaster recovery.",

                        ResourceName:
                            ResourceName(storage),

                        ResourceType:
                            ResourceType(storage)));
            }
        }
    }

    // =========================================================
    // BASIC ARCHITECTURE
    // =========================================================

    private static void AnalyzeBasicResourceDistribution(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var locations =
            resources
                .Select(
                    r => GetString(
                        r,
                        "location"))
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
        JsonElement resource,
        string type)
    {
        return string.Equals(
            GetString(
                resource,
                "type"),
            type,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string ResourceName(
        JsonElement resource)
    {
        return GetString(
                   resource,
                   "name")
               ?? "Unknown";
    }

    private static string ResourceType(
        JsonElement resource)
    {
        return GetString(
                   resource,
                   "type")
               ?? "Unknown";
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            && value.ValueKind ==
                JsonValueKind.String
            ? value.GetString()
            : null;
    }
}