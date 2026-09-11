using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CorrelationAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings =
            new List<Finding>();

        AnalyzeVmExposure(
            resources,
            findings);

        AnalyzeVmResilience(
            resources,
            findings);

        AnalyzeStorageResilience(
            resources,
            findings);

        return findings;
    }

    private static void AnalyzeVmExposure(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var resourcesById =
            resources.ToDictionary(
                resource => resource.Id.TrimEnd('/'),
                StringComparer.OrdinalIgnoreCase);

        foreach (var vm in resources.Where(
                     resource =>
                         IsType(
                             resource,
                             "Microsoft.Compute/virtualMachines")))
        {
            var nics =
                vm.Relationships
                    .Where(
                        relationship =>
                            relationship.RelationshipType ==
                            "NetworkInterface")
                    .Select(
                        relationship =>
                            FindResource(
                                resourcesById,
                                relationship.TargetResourceId))
                    .Where(
                        resource =>
                            resource != null)
                    .ToList();

            foreach (var nic in nics)
            {
                if (nic == null)
                {
                    continue;
                }

                var publicIps =
                    GetTargets(
                        nic,
                        "PublicIPAddress",
                        resourcesById)
                    .ToList();

                var nsgs =
                    GetTargets(
                        nic,
                        "NetworkSecurityGroup",
                        resourcesById)
                    .Concat(
                        GetTargetsThroughSubnet(
                            nic,
                            resourcesById))
                    .DistinctBy(
                        resource => resource.Id,
                        StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (publicIps.Count == 0 ||
                    nsgs.Count == 0)
                {
                    continue;
                }

                var exposed =
                    nsgs.Any(
                        nsg =>
                            HasManagementExposure(
                                nsg));

                if (!exposed)
                {
                    continue;
                }

                findings.Add(
                    new Finding(
                        Id:
                            $"CORR-VM-PUBLIC-IP-MGMT-EXPOSURE-{vm.Id}",

                        Category:
                            Category.Security,

                        Severity:
                            Severity.Critical,

                        RuleId:
                            "CORR-VM-PUBLIC-IP-MGMT-EXPOSURE",

                        Title:
                            "VM esposta a Internet tramite IP pubblico e regole di management",

                        Description:
                            $"La VM {vm.Name} dispone di un percorso " +
                            "verso un Public IP e almeno un NSG consente " +
                            "traffico inbound di management da Internet.",

                        Impact:
                            "La combinazione di esposizione pubblica e " +
                            "porte di management aumenta significativamente " +
                            "la superficie di attacco della VM.",

                        Recommendation:
                            "Rimuovere l'esposizione pubblica ove possibile " +
                            "e consentire l'accesso amministrativo tramite " +
                            "Private connectivity, VPN, Bastion o regole " +
                            "di rete fortemente limitate.",

                        ResourceName:
                            vm.Name,

                        ResourceType:
                            vm.Type,

                        ResourceId:
                            vm.Id));
            }
        }
    }

    private static void AnalyzeVmResilience(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        foreach (var vm in resources.Where(
                     resource =>
                         IsType(
                             resource,
                             "Microsoft.Compute/virtualMachines")))
        {
            var properties =
                vm.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var backupProtected =
                GetBool(
                    properties.Value,
                    "cloudLensBackupProtected",
                    false);

            if (backupProtected)
            {
                continue;
            }

            var hasZone =
                HasAvailabilityZone(
                    properties.Value);

            var hasAvailabilitySet =
                HasAvailabilitySet(
                    properties.Value);

            if (hasZone ||
                hasAvailabilitySet)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        $"CORR-VM-NO-BACKUP-NO-HA-{vm.Id}",

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "CORR-VM-NO-BACKUP-NO-HA",

                    Title:
                        "VM senza backup e senza ridondanza infrastrutturale",

                    Description:
                        $"La VM {vm.Name} non risulta protetta da Azure Backup " +
                        "e non risulta associata a Availability Zone o Availability Set.",

                    Impact:
                        "La combinazione aumenta il rischio di indisponibilità " +
                        "e perdita dei dati in caso di failure.",

                    Recommendation:
                        "Valutare Azure Backup e un meccanismo di ridondanza " +
                        "coerente con la criticità del workload.",

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
        var storageAccounts =
            resources
                .Where(
                    resource =>
                        IsType(
                            resource,
                            "Microsoft.Storage/storageAccounts"))
                .ToList();

        if (storageAccounts.Count == 0)
        {
            return;
        }

        var locations =
            storageAccounts
                .Select(
                    resource =>
                        resource.Location)
                .Where(
                    location =>
                        !string.IsNullOrWhiteSpace(
                            location))
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        if (locations.Count != 1)
        {
            return;
        }

        foreach (var storage in storageAccounts)
        {
            if (!IsLrs(storage))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        $"CORR-STORAGE-SINGLE-REGION-LRS-{storage.Id}",

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Medium,

                    RuleId:
                        "CORR-STORAGE-SINGLE-REGION-LRS",

                    Title:
                        "Storage Account con LRS in ambiente single-region",

                    Description:
                        $"Lo Storage Account {storage.Name} utilizza LRS " +
                        "mentre l'ambiente rilevato è distribuito in una sola region.",

                    Impact:
                        "La combinazione riduce la resilienza geografica " +
                        "della piattaforma.",

                    Recommendation:
                        "Valutare una replica ZRS, GRS o GZRS in funzione " +
                        "dei requisiti di disponibilità e disaster recovery.",

                    ResourceName:
                        storage.Name,

                    ResourceType:
                        storage.Type,

                    ResourceId:
                        storage.Id));
        }
    }

    private static bool HasManagementExposure(
        AzureResource nsg)
    {
        var properties =
            nsg.GetEffectiveProperties();

        if (!properties.HasValue)
        {
            return false;
        }

        if (!properties.Value.TryGetProperty(
                "securityRules",
                out var rules) ||
            rules.ValueKind !=
                JsonValueKind.Array)
        {
            return false;
        }

        foreach (var rule in
                 rules.EnumerateArray())
        {
            var access =
                GetString(
                    rule,
                    "access");

            var direction =
                GetString(
                    rule,
                    "direction");

            var source =
                GetString(
                    rule,
                    "sourceAddressPrefix");

            var destinationPort =
                GetString(
                    rule,
                    "destinationPortRange");

            if (!string.Equals(
                    access,
                    "Allow",
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(
                    direction,
                    "Inbound",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var publicSource =
                string.Equals(
                    source,
                    "*",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    source,
                    "Internet",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    source,
                    "0.0.0.0/0",
                    StringComparison.OrdinalIgnoreCase) ||
                string.Equals(
                    source,
                    "::/0",
                    StringComparison.OrdinalIgnoreCase);

            if (!publicSource)
            {
                continue;
            }

            if (destinationPort == "22" ||
                destinationPort == "3389" ||
                destinationPort == "*" ||
                destinationPort == "0-65535")
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<AzureResource> GetTargets(
        AzureResource resource,
        string relationshipType,
        IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        return resource.Relationships
            .Where(
                relationship =>
                    relationship.RelationshipType ==
                    relationshipType)
            .Select(
                relationship =>
                    FindResource(
                        resourcesById,
                        relationship.TargetResourceId))
            .Where(
                target =>
                    target != null)!;
    }

    private static IEnumerable<AzureResource>
        GetTargetsThroughSubnet(
            AzureResource nic,
            IReadOnlyDictionary<string, AzureResource> resourcesById)
    {
        var subnets =
            GetTargets(
                nic,
                "Subnet",
                resourcesById);

        return subnets.SelectMany(
            subnet =>
                GetTargets(
                    subnet,
                    "NetworkSecurityGroup",
                    resourcesById));
    }

    private static AzureResource? FindResource(
        IReadOnlyDictionary<string, AzureResource> resourcesById,
        string id)
    {
        var normalized =
            id.TrimEnd('/');

        return resourcesById.TryGetValue(
            normalized,
            out var resource)
            ? resource
            : null;
    }

    private static bool IsLrs(
        AzureResource resource)
    {
        if (!resource.Sku.HasValue)
        {
            return false;
        }

        if (!resource.Sku.Value.TryGetProperty(
                "name",
                out var name))
        {
            return false;
        }

        var value =
            name.GetString();

        return
            !string.IsNullOrWhiteSpace(value) &&
            value.Contains(
                "LRS",
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasAvailabilityZone(
        JsonElement properties)
    {
        return
            properties.TryGetProperty(
                "zones",
                out var zones) &&
            zones.ValueKind == JsonValueKind.Array &&
            zones.GetArrayLength() > 0;
    }

    private static bool HasAvailabilitySet(
        JsonElement properties)
    {
        return
            properties.TryGetProperty(
                "availabilitySet",
                out var availabilitySet) &&
            availabilitySet.ValueKind ==
                JsonValueKind.Object &&
            availabilitySet.TryGetProperty(
                "id",
                out var id) &&
            id.ValueKind ==
                JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(
                id.GetString());
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

    private static bool GetBool(
        JsonElement element,
        string propertyName,
        bool defaultValue)
    {
        if (!element.TryGetProperty(
                propertyName,
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
        string propertyName)
    {
        if (!element.TryGetProperty(
                propertyName,
                out var value))
        {
            return null;
        }

        return value.ValueKind ==
               JsonValueKind.String
            ? value.GetString()
            : null;
    }
}