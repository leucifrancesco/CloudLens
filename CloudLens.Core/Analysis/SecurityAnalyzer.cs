using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class SecurityAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        if (resources == null)
            throw new ArgumentNullException(nameof(resources));

        if (subscription == null)
            throw new ArgumentNullException(nameof(subscription));

        var findings = new List<Finding>();

        AnalyzeNsgs(resources, findings);
        AnalyzeStorageAccounts(resources, findings);
        AnalyzeKeyVaults(resources, findings);
        AnalyzeSqlServers(resources, findings);
        AnalyzeAppServices(resources, findings);

        return findings;
    }

    private static void AnalyzeNsgs(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        foreach (var nsg in resources.Where(
                     r => IsType(
                         r,
                         "Microsoft.Network/networkSecurityGroups")))
        {
            var properties = nsg.GetEffectiveProperties();

            if (!properties.HasValue ||
                !properties.Value.TryGetProperty(
                    "securityRules",
                    out var rules) ||
                rules.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var rule in rules.EnumerateArray())
            {
                if (!IsInboundAllowRule(rule))
                    continue;

                var source = GetString(
                    rule,
                    "sourceAddressPrefix");

                var sourcePrefixes = GetStringArray(
                    rule,
                    "sourceAddressPrefixes");

                var internetExposed =
                    string.Equals(
                        source,
                        "*",
                        StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(
                        source,
                        "Internet",
                        StringComparison.OrdinalIgnoreCase) ||
                    sourcePrefixes.Any(
                        s =>
                            s == "*" ||
                            string.Equals(
                                s,
                                "Internet",
                                StringComparison.OrdinalIgnoreCase));

                if (!internetExposed)
                    continue;

                var ports = new List<string>();

                var destinationPort = GetString(
                    rule,
                    "destinationPortRange");

                if (!string.IsNullOrWhiteSpace(destinationPort))
                {
                    ports.Add(destinationPort);
                }

                ports.AddRange(
                    GetStringArray(
                        rule,
                        "destinationPortRanges"));

                if (ports.Any(IsAnyPort))
                {
                    Add(
                        findings,
                        nsg,
                        Category.Security,
                        "SEC-NSG-INBOUND-ANY",
                        Severity.Critical,
                        "NSG consente traffico inbound Internet su qualsiasi porta",
                        "È presente una regola Allow inbound da Internet con destinazione su qualsiasi porta.",
                        "La superficie di attacco della rete è significativamente esposta.",
                        "Limitare le sorgenti e le porte alle sole necessità applicative.");

                    continue;
                }

                if (ports.Any(ContainsSsh))
                {
                    Add(
                        findings,
                        nsg,
                        Category.Security,
                        "SEC-NSG-SSH-INTERNET",
                        Severity.High,
                        "SSH esposto direttamente a Internet",
                        "Una regola NSG consente traffico SSH inbound da Internet.",
                        "Il servizio SSH è direttamente esposto a tentativi di brute force e scanning.",
                        "Limitare la sorgente tramite IP autorizzati, VPN, Bastion o altro accesso amministrativo controllato.");
                }

                if (ports.Any(ContainsRdp))
                {
                    Add(
                        findings,
                        nsg,
                        Category.Security,
                        "SEC-NSG-RDP-INTERNET",
                        Severity.High,
                        "RDP esposto direttamente a Internet",
                        "Una regola NSG consente traffico RDP inbound da Internet.",
                        "RDP direttamente esposto aumenta significativamente la superficie di attacco.",
                        "Limitare la sorgente tramite IP autorizzati, VPN, Bastion o accesso amministrativo controllato.");
                }
            }
        }
    }

    private static void AnalyzeStorageAccounts(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        foreach (var storage in resources.Where(
                     r => IsType(
                         r,
                         "Microsoft.Storage/storageAccounts")))
        {
            var properties = storage.GetEffectiveProperties();

            if (!properties.HasValue)
                continue;

            if (GetBool(
                    properties.Value,
                    "allowBlobPublicAccess",
                    false))
            {
                Add(
                    findings,
                    storage,
                    Category.Security,
                    "SEC-STORAGE-BLOB-PUBLIC",
                    Severity.High,
                    "Blob public access consentito",
                    "La Storage Account consente l'accesso pubblico ai blob.",
                    "Container o blob possono essere esposti pubblicamente se configurati in modo permissivo.",
                    "Disabilitare Allow Blob Public Access se non esplicitamente richiesto.");
            }

            if (!GetBool(
                    properties.Value,
                    "supportsHttpsTrafficOnly",
                    true))
            {
                Add(
                    findings,
                    storage,
                    Category.Security,
                    "SEC-STORAGE-HTTPS",
                    Severity.Medium,
                    "Storage Account senza HTTPS obbligatorio",
                    "La risorsa non risulta configurata per richiedere esclusivamente HTTPS.",
                    "Il traffico non cifrato può essere utilizzato dai client.",
                    "Abilitare il requisito HTTPS-only.");
            }

            var minimumTls = GetString(
                properties.Value,
                "minimumTlsVersion");

            if (string.Equals(
                    minimumTls,
                    "TLS1_0",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    minimumTls,
                    "TLS1_1",
                    StringComparison.OrdinalIgnoreCase))
            {
                Add(
                    findings,
                    storage,
                    Category.Security,
                    "SEC-STORAGE-TLS-OLD",
                    Severity.High,
                    "Storage Account con TLS obsoleto",
                    $"La Storage Account utilizza {minimumTls}.",
                    "Versioni TLS obsolete riducono il livello di sicurezza delle connessioni.",
                    "Portare il minimum TLS version ad almeno TLS 1.2 verificando la compatibilità dei client.");
            }

            var publicNetworkAccess = GetString(
                properties.Value,
                "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                Add(
                    findings,
                    storage,
                    Category.Security,
                    "SEC-STORAGE-PUBLIC-NETWORK",
                    Severity.Low,
                    "Storage Account accessibile tramite rete pubblica",
                    "La Storage Account consente accesso tramite rete pubblica.",
                    "La superficie di rete è maggiore rispetto a un'architettura completamente privata.",
                    "Valutare firewall, virtual network rules e Private Endpoint.");
            }
        }
    }

    private static void AnalyzeKeyVaults(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        foreach (var resource in resources.Where(
                     r => IsType(
                         r,
                         "Microsoft.KeyVault/vaults")))
        {
            var properties = resource.GetEffectiveProperties();

            if (!properties.HasValue)
                continue;

            var publicNetworkAccess = GetString(
                properties.Value,
                "publicNetworkAccess");

            var networkAcls = GetProperty(
                properties.Value,
                "networkAcls");

            var defaultAction =
                networkAcls.HasValue
                    ? GetString(
                        networkAcls.Value,
                        "defaultAction")
                    : null;

            var publiclyAccessible =
                string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase);

            var networkRestricted =
                string.Equals(
                    defaultAction,
                    "Deny",
                    StringComparison.OrdinalIgnoreCase);

            if (publiclyAccessible && !networkRestricted)
            {
                Add(
                    findings,
                    resource,
                    Category.Security,
                    "SEC-KV-PUBLIC-NETWORK",
                    Severity.Medium,
                    "Key Vault accessibile dalla rete pubblica senza restrizioni di rete",
                    $"Il Key Vault '{resource.Name}' consente l'accesso tramite rete pubblica e non risulta configurato con una policy network ACL predefinita di tipo Deny.",
                    "Aumenta la superficie di esposizione di segreti, chiavi e certificati.",
                    "Valutare Private Endpoint oppure configurare network ACL con default action Deny e consentire esplicitamente solo le reti necessarie.");
            }

            var purgeProtection = GetBool(
                properties.Value,
                "enablePurgeProtection",
                true);

            if (!purgeProtection)
            {
                Add(
                    findings,
                    resource,
                    Category.Security,
                    "SEC-KV-NO-PURGE",
                    Severity.Medium,
                    "Key Vault senza purge protection",
                    $"Il Key Vault '{resource.Name}' non espone la purge protection come abilitata.",
                    "Una cancellazione potrebbe diventare definitiva prima del termine della retention.",
                    "Abilitare la purge protection quando richiesta dai requisiti di sicurezza e continuità operativa.");
            }
        }
    }

    private static void AnalyzeSqlServers(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        foreach (var sql in resources.Where(
                     r => IsType(
                         r,
                         "Microsoft.Sql/servers")))
        {
            var properties = sql.GetEffectiveProperties();

            if (!properties.HasValue)
                continue;

            var publicNetworkAccess = GetString(
                properties.Value,
                "publicNetworkAccess");

            if (string.Equals(
                    publicNetworkAccess,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                Add(
                    findings,
                    sql,
                    Category.Security,
                    "SEC-SQL-PUBLIC-NETWORK",
                    Severity.Medium,
                    "Azure SQL Server con public network access",
                    "Il SQL Server consente accesso tramite rete pubblica.",
                    "La superficie di rete del database è maggiore del necessario in scenari privati.",
                    "Valutare Private Endpoint e limitazioni tramite firewall.");
            }
        }
    }

    private static void AnalyzeAppServices(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        foreach (var app in resources.Where(
                     r => IsType(
                         r,
                         "Microsoft.Web/sites")))
        {
            var properties = app.GetEffectiveProperties();

            if (!properties.HasValue)
                continue;

            if (GetBool(
                    properties.Value,
                    "httpsOnly",
                    true) == false)
            {
                Add(
                    findings,
                    app,
                    Category.Security,
                    "SEC-APP-NO-HTTPS",
                    Severity.Medium,
                    "App Service senza HTTPS Only",
                    "L'applicazione non forza HTTPS.",
                    "Le richieste HTTP possono transitare senza il livello di protezione previsto.",
                    "Abilitare HTTPS Only.");
            }
        }
    }

    private static bool IsInboundAllowRule(
        JsonElement rule)
    {
        var access = GetString(
            rule,
            "access");

        var direction = GetString(
            rule,
            "direction");

        return string.Equals(
                   access,
                   "Allow",
                   StringComparison.OrdinalIgnoreCase) &&
               string.Equals(
                   direction,
                   "Inbound",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAnyPort(string port)
    {
        return port == "*" ||
               port == "0-65535";
    }

    private static bool ContainsSsh(string port)
    {
        return ContainsPort(port, 22);
    }

    private static bool ContainsRdp(string port)
    {
        return ContainsPort(port, 3389);
    }

    private static bool ContainsPort(
        string value,
        int port)
    {
        if (value == "*")
            return true;

        foreach (var token in value.Split(
                     ',',
                     StringSplitOptions.RemoveEmptyEntries |
                     StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(
                    token,
                    out var single) &&
                single == port)
            {
                return true;
            }

            var range = token.Split('-');

            if (range.Length == 2 &&
                int.TryParse(
                    range[0],
                    out var min) &&
                int.TryParse(
                    range[1],
                    out var max) &&
                port >= min &&
                port <= max)
            {
                return true;
            }
        }

        return false;
    }

    private static string? GetString(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static bool GetBool(
        JsonElement element,
        string name,
        bool defaultValue)
    {
        if (!element.TryGetProperty(
                name,
                out var value))
        {
            return defaultValue;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => defaultValue
        };
    }

    private static List<string> GetStringArray(
        JsonElement element,
        string name)
    {
        var result = new List<string>();

        if (!element.TryGetProperty(
                name,
                out var array) ||
            array.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
                continue;

            var value = item.GetString();

            if (!string.IsNullOrWhiteSpace(value))
            {
                result.Add(value);
            }
        }

        return result;
    }

    private static JsonElement? GetProperty(
        JsonElement element,
        string name)
    {
        if (!element.TryGetProperty(
                name,
                out var value))
        {
            return null;
        }

        return value;
    }

    private static bool IsType(
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }

    private static void Add(
        List<Finding> findings,
        AzureResource resource,
        Category category,
        string ruleId,
        Severity severity,
        string title,
        string description,
        string impact,
        string recommendation)
    {
        findings.Add(
            new Finding(
                Id:
                    $"{ruleId}-{resource.Id}",

                Category:
                    category,

                Severity:
                    severity,

                RuleId:
                    ruleId,

                Title:
                    title,

                Description:
                    description,

                Impact:
                    impact,

                Recommendation:
                    recommendation,

                ResourceName:
                    resource.Name,

                ResourceType:
                    resource.Type,

                ResourceId:
                    resource.Id));
    }
}