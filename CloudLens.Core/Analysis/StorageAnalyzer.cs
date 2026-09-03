using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class StorageAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeStorageAccounts(
            resources,
            findings);

        return findings;
    }

    // ============================================================
    // STORAGE ACCOUNTS
    // ============================================================

    private static void AnalyzeStorageAccounts(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var storageAccounts = resources.Where(
            resource => TypeEquals(
                resource,
                "Microsoft.Storage/storageAccounts"));

        foreach (var storageAccount in storageAccounts)
        {
            var properties =
                GetEffectiveProperties(storageAccount);

            if (!properties.HasValue)
                continue;

            AnalyzeHttps(
                storageAccount,
                properties.Value,
                findings);

            AnalyzeTlsVersion(
                storageAccount,
                properties.Value,
                findings);

            AnalyzePublicNetworkAccess(
                storageAccount,
                properties.Value,
                findings);
        }
    }

    // ============================================================
    // HTTPS
    // ============================================================

    private static void AnalyzeHttps(
        AzureResource resource,
        JsonElement properties,
        List<Finding> findings)
    {
        var supportsHttps =
            GetBool(
                properties,
                "supportsHttpsTrafficOnly");

        // Non assumiamo nulla se la proprietà non è presente.
        if (supportsHttps != false)
            return;

        findings.Add(
            new Finding(
                Id: Guid.NewGuid().ToString(),
                Category: Category.Security,
                Severity: Severity.High,
                RuleId: "ST-NO-HTTPS",
                Title: "Traffico HTTPS non obbligatorio",
                Description:
                    $"Lo storage account '{ResourceName(resource)}' " +
                    "non obbliga l'utilizzo di HTTPS per le richieste.",
                Impact:
                    "Le comunicazioni potrebbero utilizzare HTTP e quindi " +
                    "trasmettere dati senza cifratura durante il transito.",
                Recommendation:
                    "Abilitare il requisito di traffico HTTPS per lo storage account.",
                ResourceName: ResourceName(resource),
                ResourceType: ResourceType(resource),
                ResourceId: ResourceId(resource),
                AzureCli:
                    $"az storage account update " +
                    $"--ids \"{ResourceId(resource)}\" " +
                    "--https-only true"));
    }

    // ============================================================
    // TLS VERSION
    // ============================================================

    private static void AnalyzeTlsVersion(
        AzureResource resource,
        JsonElement properties,
        List<Finding> findings)
    {
        var tlsVersion =
            GetString(
                properties,
                "minimumTlsVersion");

        if (string.IsNullOrWhiteSpace(tlsVersion))
            return;

        // Flagghiamo esclusivamente versioni note come obsolete.
        // Valori sconosciuti non vengono considerati automaticamente
        // non sicuri.
        if (!IsOldTlsVersion(tlsVersion))
            return;

        findings.Add(
            new Finding(
                Id: Guid.NewGuid().ToString(),
                Category: Category.Security,
                Severity: Severity.Medium,
                RuleId: "ST-TLS-OLD",
                Title: $"Versione TLS minima obsoleta: {tlsVersion}",
                Description:
                    $"Lo storage account '{ResourceName(resource)}' " +
                    $"utilizza '{tlsVersion}' come versione TLS minima.",
                Impact:
                    "L'utilizzo di protocolli TLS obsoleti riduce il livello " +
                    "di sicurezza delle comunicazioni verso lo storage account.",
                Recommendation:
                    "Impostare TLS 1.2 o una versione successiva supportata " +
                    "dall'ambiente e dalle applicazioni.",
                ResourceName: ResourceName(resource),
                ResourceType: ResourceType(resource),
                ResourceId: ResourceId(resource),
                AzureCli:
                    $"az storage account update " +
                    $"--ids \"{ResourceId(resource)}\" " +
                    "--min-tls-version TLS1_2"));
    }

    private static bool IsOldTlsVersion(
        string tlsVersion)
    {
        return tlsVersion.Equals(
                   "TLS1_0",
                   StringComparison.OrdinalIgnoreCase) ||
               tlsVersion.Equals(
                   "TLS1_1",
                   StringComparison.OrdinalIgnoreCase) ||
               tlsVersion.Equals(
                   "TLS1.0",
                   StringComparison.OrdinalIgnoreCase) ||
               tlsVersion.Equals(
                   "TLS1.1",
                   StringComparison.OrdinalIgnoreCase);
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

        // publicNetworkAccess = Enabled non significa
        // necessariamente che tutto Internet sia consentito.
        //
        // Se esistono network ACL con defaultAction = Deny,
        // l'accesso pubblico è comunque filtrato.
        if (!TryGetProperty(
                properties,
                "networkAcls",
                out var networkAcls))
        {
            // Non abbiamo informazioni sufficienti per stabilire
            // se l'accesso Internet sia effettivamente aperto.
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
                RuleId: "ST-PUBLIC-NETWORK",
                Title: "Storage Account accessibile dalla rete pubblica",
                Description:
                    $"Lo storage account '{ResourceName(resource)}' " +
                    "ha l'accesso dalla rete pubblica abilitato e " +
                    "le network ACL utilizzano defaultAction=Allow.",
                Impact:
                    "Le richieste provenienti da reti pubbliche non sono " +
                    "bloccate dal firewall dello storage account, aumentando " +
                    "la superficie di esposizione del servizio.",
                Recommendation:
                    "Se l'accesso pubblico non è necessario, disabilitarlo " +
                    "oppure configurare le network ACL con defaultAction=Deny " +
                    "e consentire esplicitamente le reti autorizzate.",
                ResourceName: ResourceName(resource),
                ResourceType: ResourceType(resource),
                ResourceId: ResourceId(resource),
                AzureCli:
                    $"az storage account show " +
                    $"--ids \"{ResourceId(resource)}\""));
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