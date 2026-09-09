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

        AnalyzeUnusedManagedDisks(
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
                IsManagedDisk);

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
                        Severity.High,

                    RuleId:
                        "DISK-UNATTACHED",

                    Title:
                        "Disco gestito non collegato",

                    Description:
                        $"Il disco '{resource.Name}' " +
                        "non risulta collegato ad alcuna VM.",

                    Impact:
                        "Il disco può generare un costo ricorrente " +
                        "senza essere utilizzato.",

                    Recommendation:
                        "Verificare il disco, conservarne uno snapshot " +
                        "se necessario e quindi eliminarlo.",

                    ResourceName:
                        resource.Name,

                    ResourceType:
                        resource.Type,

                    MonthlySavingEur:
                        EstimateDiskSaving(
                            properties.Value),

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
                IsPublicIp);

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
                        Severity.Medium,

                    RuleId:
                        "PIP-ORPHAN",

                    Title:
                        "Indirizzo IP pubblico non associato",

                    Description:
                        $"L'IP pubblico '{resource.Name}' " +
                        "non risulta associato ad alcuna risorsa.",

                    Impact:
                        "Possibile costo ricorrente non necessario.",

                    Recommendation:
                        "Verificare che l'IP non sia necessario " +
                        "e rimuoverlo se inutilizzato.",

                    ResourceName:
                        resource.Name,

                    ResourceType:
                        resource.Type,

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
                IsPublicIp);

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
                        Severity.Medium,

                    RuleId:
                        "PIP-BASIC-SKU",

                    Title:
                        "Public IP con SKU Basic",

                    Description:
                        $"L'IP pubblico '{resource.Name}' " +
                        "utilizza lo SKU Basic.",

                    Impact:
                        "Lo SKU Basic è una configurazione legacy " +
                        "e può richiedere migrazione verso Standard " +
                        "in base al servizio e all'architettura.",

                    Recommendation:
                        "Verificare la compatibilità e pianificare " +
                        "la migrazione a SKU Standard quando necessario.",

                    ResourceName:
                        resource.Name,

                    ResourceType:
                        resource.Type,

                    ResourceId:
                        resource.Id));
        }
    }

    // =========================================================
    // MANAGED DISK STATE
    // =========================================================

    private static void AnalyzeUnusedManagedDisks(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        /*
         * DISK-UNATTACHED identifica già i managed disk
         * non collegati.
         *
         * Manteniamo il metodo come punto di estensione
         * per future regole specifiche sullo stato del disco.
         */
    }

    // =========================================================
    // COST ESTIMATION
    // =========================================================

    private static double EstimateDiskSaving(
        JsonElement properties)
    {
        if (!properties.TryGetProperty(
                "diskSizeGB",
                out var sizeElement))
        {
            return 0;
        }

        if (!sizeElement.TryGetDouble(
                out var sizeGb))
        {
            return 0;
        }

        if (sizeGb <= 0)
        {
            return 0;
        }

        const double estimatedEurPerGbMonth =
            0.06;

        return Math.Round(
            sizeGb * estimatedEurPerGbMonth,
            2);
    }

    // =========================================================
    // RESOURCE HELPERS
    // =========================================================

    private static bool IsManagedDisk(
        AzureResource resource)
    {
        return string.Equals(
            resource.Type,
            "Microsoft.Compute/disks",
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPublicIp(
        AzureResource resource)
    {
        return string.Equals(
            resource.Type,
            "Microsoft.Network/publicIPAddresses",
            StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================
    // JSON HELPERS
    // =========================================================

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
