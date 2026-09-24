using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CostAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeUnattachedDisks(
            resources,
            findings);

        AnalyzeOrphanPublicIps(
            resources,
            findings);

        AnalyzeRetiredPublicIpSku(
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
                        $"COST-UNATTACHED-DISK-{resource.Id}",

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
                        "Un managed disk non associato può continuare " +
                        "a generare costi di storage senza fornire " +
                        "un servizio attivo.",

                    Recommendation:
                        "Verificare se il disco contiene dati necessari " +
                        "o se è utilizzato da processi di recovery, " +
                        "replica o migrazione. Se non necessario, " +
                        "conservarne una copia quando richiesto e " +
                        "procedere alla rimozione.",

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
                        $"COST-UNUSED-PIP-{resource.Id}",

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
                        "La risorsa può generare costi ricorrenti " +
                        "senza essere utilizzata.",

                    Recommendation:
                        "Verificare che l'IP pubblico non sia riservato " +
                        "per una futura configurazione o migrazione. " +
                        "Se non necessario, procedere alla rimozione.",

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
    // RETIRED PUBLIC IP SKU
    // =========================================================

    private static void AnalyzeRetiredPublicIpSku(
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
                        $"OPS-PIP-BASIC-SKU-{resource.Id}",

                    Category:
                        Category.Operations,

                    Severity:
                        Severity.High,

                    RuleId:
                        "OPS-PIP-BASIC-SKU",

                    Title:
                        "Public IP con SKU Basic ritirato",

                    Description:
                        $"L'IP pubblico '{resource.Name}' " +
                        "utilizza lo SKU Basic, ritirato da Azure " +
                        "il 30 settembre 2025.",

                    Impact:
                        "La risorsa utilizza uno SKU ritirato e " +
                        "non supportato per le normali risorse Azure. " +
                        "La configurazione può comportare rischi " +
                        "operativi e di supporto.",

                    Recommendation:
                        "Verificare la configurazione e migrare " +
                        "l'IP pubblico allo SKU Standard secondo " +
                        "la procedura Microsoft applicabile.",

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