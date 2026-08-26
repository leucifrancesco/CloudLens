using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class SecurityAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription)
    {
        var findings =
            new List<Finding>();

        AnalyzeNsgs(
            resources,
            findings);

        AnalyzeStorageAccounts(
            resources,
            findings);

        AnalyzePublicIpAddresses(
            resources,
            findings);

        return findings;
    }

    // =========================================================
    // NSG
    // =========================================================

    private static void AnalyzeNsgs(
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var nsgs =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Network/networkSecurityGroups"));

        foreach (var resource in nsgs)
        {
            if (!resource.TryGetProperty(
                    "properties",
                    out var properties))
            {
                continue;
            }

            if (!properties.TryGetProperty(
                    "securityRules",
                    out var rules) ||
                rules.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var rule in rules.EnumerateArray())
            {
                if (!rule.TryGetProperty(
                        "properties",
                        out var ruleProperties))
                {
                    continue;
                }

                var access =
                    GetString(
                        ruleProperties,
                        "access");

                var direction =
                    GetString(
                        ruleProperties,
                        "direction");

                var source =
                    GetString(
                        ruleProperties,
                        "sourceAddressPrefix");

                var destinationPort =
                    GetString(
                        ruleProperties,
                        "destinationPortRange");

                if (!string.Equals(
                        access,
                        "Allow",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!string.Equals(
                        direction,
                        "Inbound",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!IsInternetSource(source))
                {
                    continue;
                }

                if (!IsManagementPort(destinationPort))
                {
                    continue;
                }

                var portName =
                    destinationPort == "3389"
                        ? "RDP"
                        : "SSH";

                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Security,

                        Severity:
                            Severity.Critical,

                        RuleId:
                            "NSG-OPEN-MGMT",

                        Title:
                            $"Porta di gestione {portName} esposta a Internet",

                        Description:
                            $"Il NSG '{ResourceName(resource)}' " +
                            $"consente traffico inbound da Internet " +
                            $"verso {portName}.",

                        Impact:
                            "Superficie di attacco diretta verso " +
                            "un servizio di amministrazione.",

                        Recommendation:
                            "Limitare la sorgente a reti autorizzate " +
                            "oppure utilizzare Azure Bastion o JIT.",

                        ResourceName:
                            ResourceName(resource),

                        ResourceType:
                            ResourceType(resource),

                        AzureCli:
                            $"az network nsg rule list " +
                            $"--resource-group {ResourceGroup(resource)} " +
                            $"--nsg-name {ResourceName(resource)}"));
            }
        }
    }

    // =========================================================
    // STORAGE PUBLIC ACCESS
    // =========================================================

    private static void AnalyzeStorageAccounts(
        IReadOnlyList<JsonElement> resources,
        List<Finding> findings)
    {
        var storageAccounts =
            resources.Where(
                r => TypeEquals(
                    r,
                    "Microsoft.Storage/storageAccounts"));

        foreach (var resource in storageAccounts)
        {
            if (!resource.TryGetProperty(
                    "properties",
                    out var properties))
            {
                continue;
            }

            var publicAccess =
                GetBool(
                    properties,
                    "allowBlobPublicAccess");

            if (publicAccess != true)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.High,

                    RuleId:
                        "ST-PUBLIC-BLOB",

                    Title:
                        "Accesso pubblico ai blob consentito",

                    Description:
                        $"Lo storage account '{ResourceName(resource)}' " +
                        "consente l'accesso pubblico ai blob.",

                    Impact:
                        "Configurazione che può consentire " +
                        "l'esposizione involontaria di dati.",

                    Recommendation:
                        "Disabilitare l'accesso pubblico ai blob e " +
                        "utilizzare Entra ID/RBAC o SAS quando necessario.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource),

                    AzureCli:
                        $"az storage account update " +
                        $"--ids \"{ResourceId(resource)}\" " +
                        "--allow-blob-public-access false"));
        }
    }

    // =========================================================
    // PUBLIC IP
    // =========================================================

    private static void AnalyzePublicIpAddresses(
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

            if (!ipConfiguration.HasValue)
            {
                continue;
            }

            if (ipConfiguration.Value.ValueKind !=
                JsonValueKind.Null)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "PIP-UNASSOCIATED",

                    Title:
                        "Public IP non associato",

                    Description:
                        $"L'IP pubblico '{ResourceName(resource)}' " +
                        "non risulta associato ad alcuna risorsa.",

                    Impact:
                        "Una risorsa pubblicamente indirizzabile " +
                        "può rimanere inutilizzata o dimenticata.",

                    Recommendation:
                        "Verificare l'utilizzo dell'indirizzo e " +
                        "rimuoverlo se non necessario.",

                    ResourceName:
                        ResourceName(resource),

                    ResourceType:
                        ResourceType(resource)));
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static bool IsManagementPort(
        string? port)
    {
        if (string.IsNullOrWhiteSpace(port))
        {
            return false;
        }

        return port == "22" ||
               port == "3389" ||
               port == "*" ||
               port.Contains(
                   "22",
                   StringComparison.OrdinalIgnoreCase) ||
               port.Contains(
                   "3389",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInternetSource(
        string? source)
    {
        return source is "*" or
            "Internet" or
            "0.0.0.0/0" or
            "::/0";
    }

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

    private static string ResourceGroup(
        JsonElement resource)
    {
        var id =
            ResourceId(resource);

        var parts =
            id.Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries);

        var index =
            Array.FindIndex(
                parts,
                p => string.Equals(
                    p,
                    "resourceGroups",
                    StringComparison.OrdinalIgnoreCase));

        return index >= 0 &&
               index + 1 < parts.Length
            ? parts[index + 1]
            : "";
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

    private static bool? GetBool(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
                out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
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