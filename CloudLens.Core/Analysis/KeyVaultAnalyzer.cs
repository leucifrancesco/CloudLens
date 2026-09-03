using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class KeyVaultAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeKeyVaults(
            resources,
            findings);

        return findings;
    }

    // ============================================================
    // KEY VAULTS
    // ============================================================

    private static void AnalyzeKeyVaults(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var keyVaults = resources.Where(
            resource => TypeEquals(
                resource,
                "Microsoft.KeyVault/vaults"));

        foreach (var keyVault in keyVaults)
        {
            var properties =
                GetEffectiveProperties(keyVault);

            if (!properties.HasValue)
                continue;

            AnalyzePurgeProtection(
                keyVault,
                properties.Value,
                findings);

            AnalyzePublicNetworkAccess(
                keyVault,
                properties.Value,
                findings);
        }
    }

    // ============================================================
    // PURGE PROTECTION
    // ============================================================

    private static void AnalyzePurgeProtection(
        AzureResource resource,
        JsonElement properties,
        List<Finding> findings)
    {
        var purgeProtection =
            GetBool(
                properties,
                "enablePurgeProtection");

        // Se la proprietà non è disponibile, non facciamo
        // supposizioni sulla configurazione.
        if (purgeProtection != false)
            return;

        findings.Add(
            new Finding(
                Id: Guid.NewGuid().ToString(),
                Category: Category.Security,
                Severity: Severity.Medium,
                RuleId: "KV-NO-PURGE-PROTECTION",
                Title: "Purge Protection disabilitata",
                Description:
                    $"Il Key Vault '{ResourceName(resource)}' " +
                    "non ha la Purge Protection abilitata.",
                Impact:
                    "Gli oggetti eliminati dal vault possono essere " +
                    "permanentemente rimossi dopo il periodo di soft delete, " +
                    "riducendo la protezione contro eliminazioni accidentali " +
                    "o malevole.",
                Recommendation:
                    "Valutare l'abilitazione della Purge Protection, " +
                    "in particolare per Key Vault che contengono segreti, " +
                    "chiavi o certificati critici.",
                ResourceName: ResourceName(resource),
                ResourceType: ResourceType(resource),
                ResourceId: ResourceId(resource)));
    }

    // ============================================================
    // PUBLIC NETWORK ACCESS
    // ============================================================

    private static void AnalyzePublicNetworkAccess(
        AzureResource resource,
        JsonElement properties,
        List<Finding> findings)
    {
        var publicNetworkAccess =
            GetString(
                properties,
                "publicNetworkAccess");

        if (!string.Equals(
                publicNetworkAccess,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // publicNetworkAccess = Enabled non implica
        // necessariamente accesso indiscriminato da Internet.
        //
        // Il comportamento effettivo dipende anche dalle
        // network ACL del Key Vault.

        if (!TryGetProperty(
                properties,
                "networkAcls",
                out var networkAcls))
        {
            // Mancano informazioni sufficienti per determinare
            // se il firewall consenta effettivamente il traffico
            // proveniente da reti pubbliche.
            return;
        }

        var defaultAction =
            GetString(
                networkAcls,
                "defaultAction");

        if (!string.Equals(
                defaultAction,
                "Allow",
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        findings.Add(
            new Finding(
                Id: Guid.NewGuid().ToString(),
                Category: Category.Security,
                Severity: Severity.Medium,
                RuleId: "KV-PUBLIC-NETWORK",
                Title: "Key Vault accessibile dalla rete pubblica",
                Description:
                    $"Il Key Vault '{ResourceName(resource)}' " +
                    "ha l'accesso dalla rete pubblica abilitato e " +
                    "le network ACL utilizzano defaultAction=Allow.",
                Impact:
                    "Le richieste provenienti da reti pubbliche non sono " +
                    "bloccate dal firewall del Key Vault, aumentando la " +
                    "superficie di esposizione del servizio.",
                Recommendation:
                    "Se l'accesso pubblico non è necessario, disabilitarlo " +
                    "oppure configurare le network ACL con defaultAction=Deny " +
                    "e consentire esplicitamente le reti autorizzate.",
                ResourceName: ResourceName(resource),
                ResourceType: ResourceType(resource),
                ResourceId: ResourceId(resource),
                AzureCli:
                    $"az keyvault show " +
                    $"--id \"{ResourceId(resource)}\""));
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

    private static bool? GetBool(
        JsonElement element,
        string propertyName)
    {
        if (!element.TryGetProperty(
                propertyName,
                out var property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.True)
            return true;

        if (property.ValueKind == JsonValueKind.False)
            return false;

        return null;
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