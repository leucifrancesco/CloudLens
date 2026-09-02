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
                GetEffectiveProperties(resource);

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
                GetEffectiveProperties(resource);

            if (!properties.HasValue)
            {
                continue;
            }

            var ipConfiguration =
                GetProperty(
                    properties.Value,
                    "ipConfiguration");

            /*
             * Un Public IP è considerato orphan quando
             * ipConfiguration è esplicitamente null.
             *
             * Se la proprietà non è presente, non assumiamo
             * automaticamente che l'IP sia inutilizzato.
             */
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
    // MANAGED DISK STATE
    // =========================================================

    private static void AnalyzeUnusedManagedDisks(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        /*
         * Questa analisi è intenzionalmente vuota.
         *
         * DISK-UNATTACHED identifica già i managed disk
         * non collegati.
         *
         * Manteniamo il metodo per evitare di perdere il punto
         * di estensione per future regole specifiche sullo stato
         * del disco.
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

        /*
         * Stima volutamente conservativa.
         *
         * Non rappresenta un prezzo Azure ufficiale.
         * Serve solamente a fornire un ordine di grandezza
         * del possibile saving mensile.
         */
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
    // EFFECTIVE PROPERTIES
    // =========================================================

    private static JsonElement? GetEffectiveProperties(
        AzureResource resource)
    {
        /*
         * L'enrichment ARM ha priorità rispetto al payload
         * originale proveniente da Resource Graph.
         */
        if (resource.Enrichment?.Success == true &&
            resource.Enrichment.ArmResource.HasValue)
        {
            var arm =
                resource.Enrichment.ArmResource.Value;

            if (arm.TryGetProperty(
                    "properties",
                    out var armProperties))
            {
                return armProperties;
            }
        }

        /*
         * Fallback sul payload Resource Graph.
         */
        if (resource.Properties.HasValue)
        {
            return resource.Properties.Value;
        }

        return null;
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