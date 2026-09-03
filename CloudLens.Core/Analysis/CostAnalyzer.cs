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

        AnalyzeUnattachedManagedDisks(
            resources,
            findings);

        AnalyzeOrphanPublicIpAddresses(
            resources,
            findings);

        return findings;
    }

    // ============================================================
    // UNATTACHED MANAGED DISKS
    // ============================================================

    private static void AnalyzeUnattachedManagedDisks(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var disks = resources.Where(
            resource => TypeEquals(
                resource,
                "Microsoft.Compute/disks"));

        foreach (var disk in disks)
        {
            var properties =
                GetEffectiveProperties(disk);

            if (!properties.HasValue)
                continue;

            var diskState =
                GetString(
                    properties.Value,
                    "diskState");

            // Consideriamo orphan solo quando Azure espone
            // esplicitamente lo stato Unattached.
            //
            // Non deduciamo lo stato dall'assenza di managedBy,
            // perché questo potrebbe generare falsi positivi.
            if (!string.Equals(
                    diskState,
                    "Unattached",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id: Guid.NewGuid().ToString(),
                    Category: Category.Cost,
                    Severity: Severity.Medium,
                    RuleId: "DISK-UNATTACHED",
                    Title: "Managed Disk non associato",
                    Description:
                        $"Il managed disk '{ResourceName(disk)}' " +
                        "risulta esplicitamente nello stato Unattached.",
                    Impact:
                        "Il disco può continuare a generare costi di storage " +
                        "pur non essendo attualmente associato a una Virtual Machine.",
                    Recommendation:
                        "Verificare se il disco è ancora necessario. " +
                        "Se non è richiesto, valutarne la rimozione dopo aver " +
                        "verificato backup, retention e requisiti di recupero.",
                    ResourceName: ResourceName(disk),
                    ResourceType: ResourceType(disk),
                    ResourceId: ResourceId(disk),
                    AzureCli:
                        $"az disk show " +
                        $"--ids \"{ResourceId(disk)}\""));
        }
    }

    // ============================================================
    // ORPHAN PUBLIC IP ADDRESSES
    // ============================================================

    private static void AnalyzeOrphanPublicIpAddresses(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var publicIps = resources.Where(
            resource => TypeEquals(
                resource,
                "Microsoft.Network/publicIPAddresses"));

        foreach (var publicIp in publicIps)
        {
            var properties =
                GetEffectiveProperties(publicIp);

            if (!properties.HasValue)
                continue;

            // Se la proprietà non esiste, non abbiamo abbastanza
            // informazioni per dichiarare l'IP orphan.
            if (!TryGetProperty(
                    properties.Value,
                    "ipConfiguration",
                    out var ipConfiguration))
            {
                continue;
            }

            if (ipConfiguration.ValueKind != JsonValueKind.Null)
                continue;

            findings.Add(
                new Finding(
                    Id: Guid.NewGuid().ToString(),
                    Category: Category.Cost,
                    Severity: Severity.Low,
                    RuleId: "PIP-ORPHAN",
                    Title: "Public IP non associato",
                    Description:
                        $"Il Public IP '{ResourceName(publicIp)}' " +
                        "non risulta associato ad alcuna risorsa.",
                    Impact:
                        "Un Public IP non utilizzato può generare costi " +
                        "senza fornire alcun valore operativo.",
                    Recommendation:
                        "Verificare se l'indirizzo è riservato per un utilizzo futuro. " +
                        "Se non necessario, valutarne la rimozione.",
                    ResourceName: ResourceName(publicIp),
                    ResourceType: ResourceType(publicIp),
                    ResourceId: ResourceId(publicIp),
                    AzureCli:
                        $"az network public-ip show " +
                        $"--ids \"{ResourceId(publicIp)}\""));
        }
    }

    // ============================================================
    // HELPERS
    // ============================================================

    private static bool TypeEquals(
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string ResourceName(
        AzureResource resource)
    {
        return string.IsNullOrWhiteSpace(resource.Name)
            ? "(senza nome)"
            : resource.Name;
    }

    private static string ResourceType(
        AzureResource resource)
    {
        return resource.Type ?? "(tipo sconosciuto)";
    }

    private static string ResourceId(
        AzureResource resource)
    {
        return resource.Id ?? string.Empty;
    }

    private static JsonElement? GetEffectiveProperties(
        AzureResource resource)
    {
        if (resource.Enrichment?.ArmResource is JsonElement armResource)
        {
            if (armResource.ValueKind == JsonValueKind.Object &&
                armResource.TryGetProperty(
                    "properties",
                    out var enrichedProperties))
            {
                return enrichedProperties;
            }
        }

        return resource.Properties;
    }

    private static string? GetString(
        JsonElement element,
        string propertyName)
    {
        if (!element.TryGetProperty(
                propertyName,
                out var property))
        {
            return null;
        }

        if (property.ValueKind != JsonValueKind.String)
            return null;

        return property.GetString();
    }

    private static bool TryGetProperty(
        JsonElement element,
        string propertyName,
        out JsonElement value)
    {
        return element.TryGetProperty(
            propertyName,
            out value);
    }
}