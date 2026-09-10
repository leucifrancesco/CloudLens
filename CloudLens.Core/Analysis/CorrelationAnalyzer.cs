using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CorrelationAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeVmExposure(resources, findings);
        AnalyzeVmResilience(resources, findings);
        AnalyzeStorageResilience(resources, findings);

        return findings;
    }

    private static void AnalyzeVmExposure(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var vms = resources
            .Where(resource =>
                IsType(
                    resource,
                    "Microsoft.Compute/virtualMachines"))
            .ToList();

        foreach (var vm in vms)
        {
            var nics = GetRelatedResources(
                vm,
                resources,
                "NetworkInterface");

            if (nics.Count == 0)
                continue;

            var publicIpFound = false;

            var managementProtocols =
                new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

            foreach (var nic in nics)
            {
                var publicIps = GetRelatedResources(
                    nic,
                    resources,
                    "PublicIPAddress");

                if (publicIps.Count > 0)
                    publicIpFound = true;

                var nicNsgs = GetRelatedResources(
                    nic,
                    resources,
                    "NetworkSecurityGroup");

                foreach (var nsg in nicNsgs)
                {
                    foreach (var protocol in
                             GetInternetExposedManagementProtocols(nsg))
                    {
                        managementProtocols.Add(protocol);
                    }
                }

                var subnets = GetRelatedResources(
                    nic,
                    resources,
                    "Subnet");

                foreach (var subnet in subnets)
                {
                    var subnetNsgs = GetRelatedResources(
                        subnet,
                        resources,
                        "NetworkSecurityGroup");

                    foreach (var nsg in subnetNsgs)
                    {
                        foreach (var protocol in
                                 GetInternetExposedManagementProtocols(nsg))
                        {
                            managementProtocols.Add(protocol);
                        }
                    }
                }
            }

            if (!publicIpFound ||
                managementProtocols.Count == 0)
            {
                continue;
            }

            var protocolText = string.Join(
                ", ",
                managementProtocols.OrderBy(
                    protocol => protocol,
                    StringComparer.OrdinalIgnoreCase));

            findings.Add(
                new Finding(
                    Id:
                        $"CORR-VM-EXPOSURE-{vm.Id}",

                    Category:
                        Category.Security,

                    Severity:
                        Severity.Critical,

                    RuleId:
                        "CORR-VM-PUBLIC-IP-MGMT-EXPOSURE",

                    Title:
                        "VM esposta a Internet tramite Public IP e NSG",

                    Description:
                        $"La VM '{vm.Name}' è associata a una Public IP " +
                        $"e dispone di un percorso NSG che consente " +
                        $"traffico amministrativo da Internet " +
                        $"({protocolText}).",

                    Impact:
                        "La combinazione di esposizione pubblica e accesso " +
                        "amministrativo aumenta significativamente " +
                        "la superficie di attacco della VM.",

                    Recommendation:
                        "Rimuovere la Public IP quando non necessaria " +
                        "e preferire Azure Bastion, VPN, ExpressRoute " +
                        "o un percorso amministrativo privato. " +
                        "Limitare inoltre le regole NSG a sorgenti specifiche.",

                    ResourceName:
                        vm.Name,

                    ResourceType:
                        vm.Type,

                    ResourceId:
                        vm.Id));
        }
    }

    private static void AnalyzeVmResilience(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var vms = resources
            .Where(resource =>
                IsType(
                    resource,
                    "Microsoft.Compute/virtualMachines"))
            .ToList();

        foreach (var vm in vms)
        {
            var properties = vm.GetEffectiveProperties();

            if (!properties.HasValue)
                continue;

            var backupProtected = GetBool(
                properties.Value,
                "cloudLensBackupProtected",
                false);

            var hasAvailabilityZone =
                HasAvailabilityZone(properties.Value);

            var hasAvailabilitySet =
                HasAvailabilitySet(properties.Value);

            if (backupProtected ||
                hasAvailabilityZone ||
                hasAvailabilitySet)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        $"CORR-VM-RESILIENCE-{vm.Id}",

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "CORR-VM-NO-BACKUP-NO-HA",

                    Title:
                        "VM senza backup e senza ridondanza infrastrutturale",

                    Description:
                        $"La VM '{vm.Name}' non risulta protetta " +
                        "da Azure Backup e non risulta associata " +
                        "ad Availability Zone o Availability Set.",

                    Impact:
                        "La combinazione aumenta il rischio sia di perdita " +
                        "operativa dei dati sia di indisponibilità della VM.",

                    Recommendation:
                        "Verificare i requisiti di continuità del workload " +
                        "e configurare Azure Backup e una strategia " +
                        "di ridondanza coerente con RTO e RPO.",

                    ResourceName:
                        vm.Name,

                    ResourceType:
                        vm.Type,

                    ResourceId:
                        vm.Id));
        }
    }

    private static void AnalyzeStorageResilience(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var storageAccounts = resources
            .Where(resource =>
                IsType(
                    resource,
                    "Microsoft.Storage/storageAccounts"))
            .ToList();

        if (storageAccounts.Count == 0)
            return;

        var locations = storageAccounts
            .Select(storage => storage.Location)
            .Where(location =>
                !string.IsNullOrWhiteSpace(location))
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (locations.Count != 1)
            return;

        foreach (var storage in storageAccounts)
        {
            if (!IsLrs(storage))
                continue;

            findings.Add(
                new Finding(
                    Id:
                        $"CORR-STORAGE-RESILIENCE-{storage.Id}",

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "CORR-STORAGE-SINGLE-REGION-LRS",

                    Title:
                        "Storage Account con LRS in ambiente single-region",

                    Description:
                        $"Lo Storage Account '{storage.Name}' " +
                        $"utilizza LRS e gli Storage Account analizzati " +
                        $"sono tutti concentrati nella region " +
                        $"'{locations[0]}'.",

                    Impact:
                        "La combinazione riduce la resilienza rispetto " +
                        "a configurazioni con ridondanza zonale o geografica.",

                    Recommendation:
                        "Valutare ZRS, GRS o GZRS in funzione dei requisiti " +
                        "di disponibilità, disaster recovery e workload.",

                    ResourceName:
                        storage.Name,

                    ResourceType:
                        storage.Type,

                    ResourceId:
                        storage.Id));
        }
    }

    private static List<AzureResource> GetRelatedResources(
        AzureResource source,
        IReadOnlyList<AzureResource> resources,
        string relationshipType)
    {
        var targetIds = source.Relationships
            .Where(relationship =>
                string.Equals(
                    relationship.RelationshipType,
                    relationshipType,
                    StringComparison.OrdinalIgnoreCase))
            .Select(relationship =>
                relationship.TargetResourceId)
            .ToHashSet(
                StringComparer.OrdinalIgnoreCase);

        if (targetIds.Count == 0)
            return [];

        return resources
            .Where(resource =>
                targetIds.Contains(resource.Id))
            .ToList();
    }

    private static List<string>
        GetInternetExposedManagementProtocols(
            AzureResource nsg)
    {
        var result =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        var properties = nsg.GetEffectiveProperties();

        if (!properties.HasValue)
            return [];

        if (!properties.Value.TryGetProperty(
                "securityRules",
                out var securityRules) ||
            securityRules.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        foreach (var rule in
                 securityRules.EnumerateArray())
        {
            if (!IsInboundAllowRuleFromInternet(rule))
                continue;

            var destinationPorts =
                GetDestinationPorts(rule);

            foreach (var port in destinationPorts)
            {
                switch (port)
                {
                    case "22":
                        result.Add("SSH/22");
                        break;

                    case "3389":
                        result.Add("RDP/3389");
                        break;
                }
            }
        }

        return result.ToList();
    }

    private static bool IsInboundAllowRuleFromInternet(
        JsonElement rule)
    {
        var direction = GetString(
            rule,
            "direction");

        var access = GetString(
            rule,
            "access");

        if (!string.Equals(
                direction,
                "Inbound",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(
                access,
                "Allow",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var sourcePrefixes =
            GetStringArray(
                rule,
                "sourceAddressPrefixes");

        var sourcePrefix =
            GetString(
                rule,
                "sourceAddressPrefix");

        if (!string.IsNullOrWhiteSpace(sourcePrefix))
            sourcePrefixes.Add(sourcePrefix);

        return sourcePrefixes.Any(prefix =>
            string.Equals(
                prefix,
                "*",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                prefix,
                "Internet",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                prefix,
                "0.0.0.0/0",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                prefix,
                "::/0",
                StringComparison.OrdinalIgnoreCase));
    }

    private static List<string> GetDestinationPorts(
        JsonElement rule)
    {
        var result =
            GetStringArray(
                rule,
                "destinationPortRanges");

        var single =
            GetString(
                rule,
                "destinationPortRange");

        if (!string.IsNullOrWhiteSpace(single))
            result.Add(single);

        return result;
    }

    private static bool HasAvailabilityZone(
        JsonElement properties)
    {
        if (!properties.TryGetProperty(
                "zones",
                out var zones))
        {
            return false;
        }

        return zones.ValueKind == JsonValueKind.Array &&
               zones.GetArrayLength() > 0;
    }

    private static bool HasAvailabilitySet(
        JsonElement properties)
    {
        if (!properties.TryGetProperty(
                "availabilitySet",
                out var availabilitySet) ||
            availabilitySet.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (!availabilitySet.TryGetProperty(
                "id",
                out var id))
        {
            return false;
        }

        return id.ValueKind == JsonValueKind.String &&
               !string.IsNullOrWhiteSpace(id.GetString());
    }

    private static bool IsLrs(
        AzureResource resource)
    {
        if (resource.Sku is not JsonElement sku)
            return false;

        var name = GetString(
            sku,
            "name");

        return !string.IsNullOrWhiteSpace(name) &&
               name.Contains(
                   "LRS",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool GetBool(
        JsonElement element,
        string property,
        bool defaultValue)
    {
        if (!element.TryGetProperty(
                property,
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

    private static string? GetString(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
                out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static List<string> GetStringArray(
        JsonElement element,
        string property)
    {
        var result = new List<string>();

        if (!element.TryGetProperty(
                property,
                out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(item.GetString()))
            {
                result.Add(item.GetString()!);
            }
        }

        return result;
    }

    private static bool IsType(
        AzureResource resource,
        string expectedType)
    {
        return string.Equals(
            resource.Type,
            expectedType,
            StringComparison.OrdinalIgnoreCase);
    }
}
