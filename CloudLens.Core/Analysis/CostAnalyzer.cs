using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CostAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings =
            new List<Finding>();

        AnalyzeUnattachedDisks(
            resources,
            findings);

        AnalyzeOrphanPublicIps(
            resources,
            findings);

        AnalyzePublicIpSku(
            resources,
            findings);

        return findings;
    }

    // =========================================================
    // UNATTACHED DISKS
    // =========================================================

    private static void AnalyzeUnattachedDisks(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var disks =
            resources.Where(
                resource =>
                    IsType(
                        resource,
                        "Microsoft.Compute/disks"));

        foreach (var resource in disks)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var managedBy =
                GetString(
                    properties.Value,
                    "managedBy");

            if (!string.IsNullOrWhiteSpace(managedBy))
            {
                continue;
            }

            var diskState =
                GetString(
                    properties.Value,
                    "diskState");

            if (!string.IsNullOrWhiteSpace(diskState) &&
                !string.Equals(
                    diskState,
                    "Unattached",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Cost,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "COST-UNATTACHED-DISK",

                    Title:
                        "Managed Disk non associato",

                    Description:
                        $"Il managed disk '{resource.Name}' " +
                        "non risulta associato ad alcuna VM.",

                    Impact:
                        "Il disco può generare un costo ricorrente " +
                        "senza essere utilizzato.",

                    Recommendation:
                        "Verificare se il disco è realmente inutilizzato. " +
                        "Se non necessario, conservarne uno snapshot quando " +
                        "richiesto e quindi procedere alla rimozione.",

                    ResourceName:
                        resource.Name,

                    ResourceType:
                        resource.Type,

                    MonthlySavingEur:
                        0,

                    AzureCli:
                        $"az disk delete " +
                        $"--ids \"{resource.Id}\" --yes",

                    ResourceId:
                        resource.Id));
        }
    }

    // =========================================================
    // ORPHAN PUBLIC IP
    // =========================================================

    private static void AnalyzeOrphanPublicIps(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var publicIps =
            resources.Where(
                resource =>
                    IsType(
                        resource,
                        "Microsoft.Network/publicIPAddresses"));

        foreach (var resource in publicIps)
        {
            var properties =
                resource.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var ipConfiguration =
                GetProperty(
                    properties.Value,
                    "ipConfiguration");

            if (!ipConfiguration.HasValue ||
                ipConfiguration.Value.ValueKind !=
                    JsonValueKind.Null)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Cost,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "COST-UNUSED-PIP",

                    Title:
                        "Public IP non utilizzata",

                    Description:
                        $"L'IP pubblico '{resource.Name}' " +
                        "non risulta associato ad alcuna risorsa.",

                    Impact:
                        "Possibile costo ricorrente non necessario " +
                        "e risorsa inutilizzata nell'ambiente.",

                    Recommendation:
                        "Verificare che l'IP non sia necessario " +
                        "e rimuoverlo se inutilizzato.",

                    ResourceName:
                        resource.Name,

                    ResourceType:
                        resource.Type,

                    MonthlySavingEur:
                        0,

                    AzureCli:
                        $"az network public-ip delete " +
                        $"--ids \"{resource.Id}\"",

                    ResourceId:
                        resource.Id));
        }
    }

    // =========================================================
    // PUBLIC IP SKU
    // =========================================================

    private static void AnalyzePublicIpSku(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var publicIps =
            resources.Where(
                resource =>
                    IsType(
                        resource,
                        "Microsoft.Network/publicIPAddresses"));

        foreach (var resource in publicIps)
        {
            if (resource.Sku is not JsonElement sku)
            {
                continue;
            }

            var skuName =
                GetString(
                    sku,
                    "name");

            if (!string.Equals(
                    skuName,
                    "Basic",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Cost,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "COST-PIP-BASIC-SKU",

                    Title:
                        "Public IP con SKU Basic",

                    Description:
                        $"L'IP pubblico '{resource.Name}' " +
                        "utilizza lo SKU Basic.",

                    Impact:
                        "Lo SKU Basic è una configurazione legacy " +
                        "e può richiedere migrazione verso Standard.",

                    Recommendation:
                        "Verificare la compatibilità della configurazione " +
                        "e pianificare la migrazione a SKU Standard quando necessario.",

                    ResourceName:
                        resource.Name,

                    ResourceType:
                        resource.Type,

                    MonthlySavingEur:
                        0,

                    ResourceId:
                        resource.Id));
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static bool IsType(
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
                out var value))
        {
            return null;
        }

        return value.ValueKind ==
               JsonValueKind.String
            ? value.GetString()
            : value.ToString();
    }

    private static JsonElement? GetProperty(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            ? value
            : null;
    }
}