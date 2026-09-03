using System.Globalization;
using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class SecurityAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeNsgs(resources, findings);
        AnalyzeStorageAccounts(resources, findings);

        return findings;
    }

    // ============================================================
    // NSG ANALYSIS
    // ============================================================

    private static void AnalyzeNsgs(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var nsgs = resources.Where(
            r => TypeEquals(
                r,
                "Microsoft.Network/networkSecurityGroups"));

        foreach (var nsg in nsgs)
        {
            var properties = GetEffectiveProperties(nsg);

            if (!properties.HasValue)
                continue;

            if (!TryGetProperty(
                    properties.Value,
                    "securityRules",
                    out var rules) ||
                rules.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var publiclyExposed = IsNsgPubliclyExposed(
                nsg,
                resources);

            foreach (var rule in rules.EnumerateArray())
            {
                if (!TryGetProperty(
                        rule,
                        "properties",
                        out var ruleProperties))
                {
                    continue;
                }

                var access = GetString(
                    ruleProperties,
                    "access");

                var direction = GetString(
                    ruleProperties,
                    "direction");

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

                var sources = GetSourcePrefixes(
                    ruleProperties);

                if (!sources.Any(IsInternetSource))
                    continue;

                var protocols = GetProtocolValues(
                    ruleProperties);

                var destinationPorts =
                    GetDestinationPorts(ruleProperties);

                var ruleName = GetString(
                    rule,
                    "name") ?? "security rule";

                // ------------------------------------------------
                // ANY / ANY
                // ------------------------------------------------

                var anyProtocol =
                    protocols.Any(IsAnyProtocol);

                var anyPort =
                    destinationPorts.Any(IsAnyPort);

                if (anyProtocol && anyPort)
                {
                    findings.Add(
                        CreateFinding(
                            category: Category.Security,
                            severity: publiclyExposed
                                ? Severity.Critical
                                : Severity.High,
                            ruleId: "NSG-ANY-ANY",
                            title: "Regola NSG inbound Any/Any da Internet",
                            description:
                                $"Il NSG '{ResourceName(nsg)}' " +
                                $"contiene la regola '{ruleName}' " +
                                "che consente traffico inbound da Internet " +
                                "verso qualsiasi protocollo e porta.",
                            impact:
                                publiclyExposed
                                    ? "La regola può esporre direttamente una risorsa raggiungibile tramite Public IP a traffico Internet non limitato."
                                    : "La regola è eccessivamente permissiva e può diventare pericolosa se il NSG viene associato a una risorsa pubblicamente raggiungibile.",
                            recommendation:
                                "Limitare sorgenti, protocolli e porte alle sole comunicazioni necessarie. Verificare inoltre che eventuali endpoint pubblici siano intenzionali.",
                            resource: nsg,
                            cli:
                                $"az network nsg rule list " +
                                $"--resource-group {ResourceGroup(nsg)} " +
                                $"--nsg-name {ResourceName(nsg)}"));

                    // Una regola Any/Any è già più specifica e grave
                    // rispetto ai controlli sulle singole porte.
                    continue;
                }

                // ------------------------------------------------
                // SSH / RDP
                // ------------------------------------------------

                var managementPorts =
                    destinationPorts
                        .Where(IsManagementPort)
                        .ToList();

                if (managementPorts.Count > 0)
                {
                    foreach (var port in managementPorts)
                    {
                        var managementName =
                            IsRdpPort(port)
                                ? "RDP"
                                : IsSshPort(port)
                                    ? "SSH"
                                    : "SSH/RDP";

                        findings.Add(
                            CreateFinding(
                                category: Category.Security,
                                severity: publiclyExposed
                                    ? Severity.Critical
                                    : Severity.High,
                                ruleId: "NSG-OPEN-MGMT",
                                title:
                                    $"Porta di gestione {managementName} " +
                                    "esposta a Internet",
                                description:
                                    $"Il NSG '{ResourceName(nsg)}' " +
                                    $"contiene la regola '{ruleName}' " +
                                    $"che consente traffico inbound da Internet " +
                                    $"verso {managementName} " +
                                    $"({FormatPort(port)}).",
                                impact:
                                    publiclyExposed
                                        ? "La porta di amministrazione è raggiungibile attraverso un endpoint pubblico, aumentando significativamente la superficie di attacco."
                                        : "La regola consente accesso Internet alla porta di amministrazione; l'esposizione effettiva dipende dalla presenza di un endpoint pubblico.",
                                recommendation:
                                    "Limitare la sorgente a reti amministrative autorizzate oppure utilizzare Azure Bastion, JIT o un altro meccanismo di accesso controllato.",
                                resource: nsg,
                                cli:
                                    $"az network nsg rule list " +
                                    $"--resource-group {ResourceGroup(nsg)} " +
                                    $"--nsg-name {ResourceName(nsg)}"));
                    }

                    continue;
                }

                // ------------------------------------------------
                // HTTP / HTTPS
                // ------------------------------------------------

                var webPorts =
                    destinationPorts
                        .Where(IsWebPort)
                        .ToList();

                if (webPorts.Count > 0)
                {
                    foreach (var port in webPorts)
                    {
                        var webName =
                            IsHttpsPort(port)
                                ? "HTTPS"
                                : "HTTP";

                        findings.Add(
                            CreateFinding(
                                category: Category.Security,
                                severity: Severity.Medium,
                                ruleId: "NSG-OPEN-WEB",
                                title:
                                    $"Porta {webName} aperta a Internet",
                                description:
                                    $"Il NSG '{ResourceName(nsg)}' " +
                                    $"contiene la regola '{ruleName}' " +
                                    $"che consente traffico inbound da Internet " +
                                    $"verso {webName} ({FormatPort(port)}).",
                                impact:
                                    "L'esposizione pubblica può essere intenzionale per un servizio web, ma aumenta la superficie di attacco e deve essere coerente con l'architettura prevista.",
                                recommendation:
                                    "Verificare che l'esposizione sia intenzionale. Limitare la sorgente quando possibile e assicurarsi che il servizio utilizzi HTTPS e adeguati controlli applicativi.",
                                resource: nsg,
                                cli:
                                    $"az network nsg rule list " +
                                    $"--resource-group {ResourceGroup(nsg)} " +
                                    $"--nsg-name {ResourceName(nsg)}"));
                    }
                }
            }
        }
    }

    // ============================================================
    // STORAGE SECURITY
    // ============================================================

    private static void AnalyzeStorageAccounts(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var storageAccounts = resources.Where(
            r => TypeEquals(
                r,
                "Microsoft.Storage/storageAccounts"));

        foreach (var resource in storageAccounts)
        {
            var properties = GetEffectiveProperties(resource);

            if (!properties.HasValue)
                continue;

            AnalyzePublicBlobAccess(
                resource,
                properties.Value,
                findings);
        }
    }

    private static void AnalyzePublicBlobAccess(
        AzureResource resource,
        JsonElement properties,
        List<Finding> findings)
    {
        var publicAccess = GetBool(
            properties,
            "allowBlobPublicAccess");

        if (publicAccess != true)
            return;

        findings.Add(
            new Finding(
                Id: Guid.NewGuid().ToString(),
                Category: Category.Security,
                Severity: Severity.Medium,
                RuleId: "ST-PUBLIC-BLOB",
                Title: "Accesso anonimo ai blob consentito",
                Description:
                    $"Lo storage account '{ResourceName(resource)}' " +
                    "consente di configurare container o blob " +
                    "per l'accesso anonimo pubblico.",
                Impact:
                    "La configurazione non rende automaticamente pubblici i dati, " +
                    "ma consente l'utilizzo dell'accesso anonimo e aumenta il rischio " +
                    "di esposizione accidentale di dati.",
                Recommendation:
                    "Disabilitare l'accesso pubblico ai blob se non è esplicitamente richiesto " +
                    "e preferire Entra ID/RBAC o altri meccanismi di accesso autenticato.",
                ResourceName: ResourceName(resource),
                ResourceType: ResourceType(resource),
                ResourceId: ResourceId(resource),
                AzureCli:
                    $"az storage account update " +
                    $"--ids \"{ResourceId(resource)}\" " +
                    "--allow-blob-public-access false"));
    }

    // ============================================================
    // PUBLIC EXPOSURE CORRELATION
    // ============================================================

    private static bool IsNsgPubliclyExposed(
        AzureResource nsg,
        IReadOnlyList<AzureResource> resources)
    {
        var nsgId = NormalizeId(nsg.Id);

        // --------------------------------------------------------
        // 1. NSG associato direttamente a una NIC
        // --------------------------------------------------------

        var networkInterfaces = resources.Where(
            resource =>
                TypeEquals(
                    resource,
                    "Microsoft.Network/networkInterfaces") &&
                HasRelationshipTarget(
                    resource,
                    "NetworkSecurityGroup",
                    nsgId));

        foreach (var nic in networkInterfaces)
        {
            if (HasPublicIpRelationship(
                    nic,
                    resources))
            {
                return true;
            }
        }

        // --------------------------------------------------------
        // 2. NSG associato a una subnet
        // --------------------------------------------------------

        var subnets = resources.Where(
            resource =>
                TypeEquals(
                    resource,
                    "Microsoft.Network/virtualNetworks/subnets") &&
                HasRelationshipTarget(
                    resource,
                    "NetworkSecurityGroup",
                    nsgId));

        foreach (var subnet in subnets)
        {
            var subnetId = NormalizeId(subnet.Id);

            var subnetNics = resources.Where(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Network/networkInterfaces") &&
                    HasRelationshipTarget(
                        resource,
                        "Subnet",
                        subnetId));

            foreach (var nic in subnetNics)
            {
                if (HasPublicIpRelationship(
                        nic,
                        resources))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool HasPublicIpRelationship(
        AzureResource networkInterface,
        IReadOnlyList<AzureResource> resources)
    {
        var publicIpRelationship =
            networkInterface.Relationships.Any(
                relationship =>
                    string.Equals(
                        relationship.RelationshipType,
                        "PublicIPAddress",
                        StringComparison.OrdinalIgnoreCase) &&
                    resources.Any(
                        resource =>
                            string.Equals(
                                NormalizeId(resource.Id),
                                NormalizeId(
                                    relationship.TargetResourceId),
                                StringComparison.OrdinalIgnoreCase) &&
                            TypeEquals(
                                resource,
                                "Microsoft.Network/publicIPAddresses")));

        return publicIpRelationship;
    }

    private static bool HasRelationshipTarget(
        AzureResource resource,
        string relationshipType,
        string targetId)
    {
        return resource.Relationships.Any(
            relationship =>
                string.Equals(
                    relationship.RelationshipType,
                    relationshipType,
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    NormalizeId(
                        relationship.TargetResourceId),
                    targetId,
                    StringComparison.OrdinalIgnoreCase));
    }

    // ============================================================
    // NSG SOURCE HELPERS
    // ============================================================

    private static IEnumerable<string> GetSourcePrefixes(
        JsonElement properties)
    {
        var singular =
            GetString(
                properties,
                "sourceAddressPrefix");

        if (!string.IsNullOrWhiteSpace(singular))
            yield return singular;

        if (TryGetProperty(
                properties,
                "sourceAddressPrefixes",
                out var prefixes) &&
            prefixes.ValueKind == JsonValueKind.Array)
        {
            foreach (var prefix in prefixes.EnumerateArray())
            {
                if (prefix.ValueKind != JsonValueKind.String)
                    continue;

                var value = prefix.GetString();

                if (!string.IsNullOrWhiteSpace(value))
                    yield return value;
            }
        }
    }

    private static bool IsInternetSource(
        string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
            return false;

        return source.Equals(
                   "*",
                   StringComparison.OrdinalIgnoreCase) ||
               source.Equals(
                   "Internet",
                   StringComparison.OrdinalIgnoreCase) ||
               source.Equals(
                   "0.0.0.0/0",
                   StringComparison.OrdinalIgnoreCase) ||
               source.Equals(
                   "::/0",
                   StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================
    // NSG PROTOCOL HELPERS
    // ============================================================

    private static IEnumerable<string> GetProtocolValues(
        JsonElement properties)
    {
        var protocol =
            GetString(
                properties,
                "protocol");

        if (!string.IsNullOrWhiteSpace(protocol))
            yield return protocol;
    }

    private static bool IsAnyProtocol(
        string protocol)
    {
        return protocol.Equals(
                   "*",
                   StringComparison.OrdinalIgnoreCase) ||
               protocol.Equals(
                   "Any",
                   StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================
    // NSG PORT HELPERS
    // ============================================================

    private static IEnumerable<string> GetDestinationPorts(
        JsonElement properties)
    {
        var singular =
            GetString(
                properties,
                "destinationPortRange");

        if (!string.IsNullOrWhiteSpace(singular))
        {
            foreach (var port in SplitPortExpression(singular))
                yield return port;
        }

        if (TryGetProperty(
                properties,
                "destinationPortRanges",
                out var ranges) &&
            ranges.ValueKind == JsonValueKind.Array)
        {
            foreach (var range in ranges.EnumerateArray())
            {
                if (range.ValueKind != JsonValueKind.String)
                    continue;

                var value = range.GetString();

                if (string.IsNullOrWhiteSpace(value))
                    continue;

                foreach (var port in SplitPortExpression(value))
                    yield return port;
            }
        }
    }

    private static IEnumerable<string> SplitPortExpression(
        string value)
    {
        foreach (var item in value.Split(
                     ',',
                     StringSplitOptions.RemoveEmptyEntries |
                     StringSplitOptions.TrimEntries))
        {
            if (!string.IsNullOrWhiteSpace(item))
                yield return item;
        }
    }

    private static bool IsAnyPort(
        string? port)
    {
        return string.Equals(
            port,
            "*",
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsManagementPort(
        string? port)
    {
        return IsSshPort(port) ||
               IsRdpPort(port);
    }

    private static bool IsSshPort(
        string? port)
    {
        return ContainsPort(
            port,
            22);
    }

    private static bool IsRdpPort(
        string? port)
    {
        return ContainsPort(
            port,
            3389);
    }

    private static bool IsWebPort(
        string? port)
    {
        return ContainsPort(port, 80) ||
               ContainsPort(port, 443);
    }

    private static bool IsHttpsPort(
        string? port)
    {
        return ContainsPort(
            port,
            443);
    }

    private static bool ContainsPort(
        string? expression,
        int targetPort)
    {
        if (string.IsNullOrWhiteSpace(expression))
            return false;

        if (expression == "*")
            return true;

        var normalized =
            expression.Trim();

        // Exact numeric port
        if (int.TryParse(
                normalized,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var exactPort))
        {
            return exactPort == targetPort;
        }

        // Range, e.g. 20-23
        var separatorIndex =
            normalized.IndexOf('-');

        if (separatorIndex > 0)
        {
            var startText =
                normalized[..separatorIndex].Trim();

            var endText =
                normalized[(separatorIndex + 1)..].Trim();

            if (int.TryParse(
                    startText,
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out var start) &&
                int.TryParse(
                    endText,
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out var end))
            {
                if (start > end)
                    (start, end) = (end, start);

                return targetPort >= start &&
                       targetPort <= end;
            }
        }

        return false;
    }

    private static string FormatPort(
        string port)
    {
        return port == "*"
            ? "tutte le porte"
            : port;
    }

    // ============================================================
    // FINDING FACTORY
    // ============================================================

    private static Finding CreateFinding(
        Category category,
        Severity severity,
        string ruleId,
        string title,
        string description,
        string impact,
        string recommendation,
        AzureResource resource,
        string? cli = null)
    {
        return new Finding(
            Id: Guid.NewGuid().ToString(),
            Category: category,
            Severity: severity,
            RuleId: ruleId,
            Title: title,
            Description: description,
            Impact: impact,
            Recommendation: recommendation,
            ResourceName: ResourceName(resource),
            ResourceType: ResourceType(resource),
            ResourceId: ResourceId(resource),
            AzureCli: cli);
    }

    // ============================================================
    // GENERIC AZURE RESOURCE HELPERS
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

    private static string ResourceGroup(
        AzureResource resource)
    {
        return resource.ResourceGroup ?? string.Empty;
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

    private static JsonElement? GetProperty(
        JsonElement element,
        string propertyName)
    {
        return element.TryGetProperty(
            propertyName,
            out var property)
            ? property
            : null;
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

    private static string NormalizeId(
        string? id)
    {
        return (id ?? string.Empty).Trim().TrimEnd('/');
    }
}