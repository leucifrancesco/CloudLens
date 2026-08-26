using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CostAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
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
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var disks =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Compute/disks"));

        foreach (var resource in disks)
        {
            if (!resource.TryGetProperty(
                    "properties",
                    out var properties))
            {
                continue;
            }

            var managedBy =
                GetString(
                    properties,
                    "managedBy");

            if (!string.IsNullOrWhiteSpace(managedBy))
            {
                continue;
            }

            var diskState =
                GetString(
                    properties,
                    "diskState");

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
                        $"Il disco '{ResourceName(resource)}' " +
                        "non risulta collegato ad alcuna VM.",

                    Impact:
                        "Il disco può generare un costo ricorrente " +
                        "senza essere utilizzato.",

                    Recommendation:
                        "Verificare il disco, conservarne uno snapshot " +
                        "se necessario e quindi eliminarlo.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    MonthlySavingEur:
                        EstimateDiskSaving(
                            properties),

                    AzureCli:
                        $"az disk delete " +
                        $"--ids \"{ResourceId(resource)}\" --yes"));
        }
    }

    // =========================================================
    // ORPHAN PUBLIC IP
    // =========================================================

    private static void AnalyzeOrphanPublicIps(
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var publicIps =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Network/publicIPAddresses"));

        foreach (var resource in publicIps)
        {
            if (!resource.TryGetProperty(
                    "properties",
                    out var properties))
            {
                continue;
            }

            var ipConfiguration =
                GetProperty(
                    properties,
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
                        $"L'IP pubblico '{ResourceName(resource)}' " +
                        "non risulta associato ad alcuna risorsa.",

                    Impact:
                        "Possibile costo ricorrente non necessario.",

                    Recommendation:
                        "Verificare che l'IP non sia necessario " +
                        "e rimuoverlo se inutilizzato.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    AzureCli:
                        $"az network public-ip delete " +
                        $"--ids \"{ResourceId(resource)}\""));
        }
    }

    // =========================================================
    // MANAGED DISK STATE
    // =========================================================

    private static void AnalyzeUnusedManagedDisks(
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var disks =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Compute/disks"));

        foreach (var resource in disks)
        {
            if (!resource.TryGetProperty(
                    "properties",
                    out var properties))
            {
                continue;
            }

            var managedBy =
                GetString(
                    properties,
                    "managedBy");

            var diskState =
                GetString(
                    properties,
                    "diskState");

            if (!string.IsNullOrWhiteSpace(managedBy) ||
                !string.Equals(
                    diskState,
                    "Unattached",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // DISK-UNATTACHED ha già identificato il disco.
            // Evitiamo un secondo finding duplicato.
        }
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
         * Non viene presentato come prezzo Azure ufficiale:
         * serve soltanto per quantificare l'ordine di grandezza
         * del possibile saving.
         */
        const double estimatedEurPerGbMonth =
            0.06;

        return Math.Round(
            sizeGb * estimatedEurPerGbMonth,
            2);
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static bool TypeEquals(
        JsonElement resource,
        string type)
    {
        return string.Equals(
            GetString(resource, "type"),
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

    private static string ResourceId(
        JsonElement resource)
    {
        return GetString(
                   resource,
                   "id")
               ?? "";
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            ? value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : value.ToString()
            : null;
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