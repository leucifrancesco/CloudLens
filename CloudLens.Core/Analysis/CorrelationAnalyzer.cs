using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class CorrelationAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(subscription);

        var findings = new List<Finding>();

        AnalyzeVmExposure(resources, findings);
        AnalyzeVmResilience(resources, findings);
        AnalyzeStorageResilience(
            resources,
            subscription,
            findings);

        return findings;
    }

    private static void AnalyzeVmExposure(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var resourcesById = resources
            .Where(resource => !string.IsNullOrWhiteSpace(resource.Id))
            .GroupBy(
                resource => resource.Id.TrimEnd('/'),
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.First(),
                StringComparer.OrdinalIgnoreCase);

        foreach (var vm in resources.Where(
                     resource => IsType(
                         resource,
                         "Microsoft.Compute/virtualMachines")))
        {
            var nics = vm.Relationships
                .Where(relationship =>
                    string.Equals(
                        relationship.RelationshipType,
                        "NetworkInterface",
                        StringComparison.OrdinalIgnoreCase))
                .Select(relationship =>
                    FindResource(
                        resourcesById,
                        relationship.TargetResourceId))
                .OfType<AzureResource>()
                .ToList();

            foreach (var nic in nics)
            {
                var publicIps = GetTargets(
                        nic,
                        "PublicIPAddress",
                        resourcesById)
                    .ToList();

                var nsgs = GetTargets(
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

                if (publicIps.Count == 0 || nsgs.Count == 0)
                {
                    continue;
                }

                var exposed =
                    nsgs.Any(HasManagementExposure);

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
                            $"La VM '{vm.Name}' dispone di un percorso " +
                            "verso un Public IP e almeno un NSG consente " +
                            "traffico inbound di management da Internet.",
                        Impact:
                            "La combinazione di esposizione pubblica e " +
                            "porte di management aumenta la superficie " +
                            "di attacco della VM.",
                        Recommendation:
                            "Rimuovere l'esposizione pubblica ove possibile " +
                            "e consentire l'accesso amministrativo tramite " +
                            "connettività privata, VPN, Bastion o regole " +
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
                     resource => IsType(
                         resource,
                         "Microsoft.Compute/virtualMachines")))
        {
            var properties =
                vm.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            // Il dato deve essere disponibile ed esplicitamente false.
            // Un dato assente o non valido non equivale a backup assente.
            if (!TryGetBool(
                    properties.Value,
                    "cloudLensBackupProtected",
                    out var backupProtected))
            {
                continue;
            }

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

            if (hasZone || hasAvailabilitySet)
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
                        $"La VM '{vm.Name}' non risulta protetta da Azure Backup " +
                        "e non risulta associata ad Availability Zone o " +
                        "Availability Set, sulla base dei dati raccolti.",
                    Impact:
                        "La combinazione può aumentare il rischio di " +
                        "indisponibilità e perdita dei dati in caso di failure.",
                    Recommendation:
                        "Verificare RPO, RTO e requisiti di disponibilità " +
                        "del workload. Valutare una policy Azure Backup e " +
                        "una configurazione di ridondanza coerente con " +
                        "la criticità del servizio.",
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
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var storageAccounts = resources
            .Where(
                resource => IsType(
                    resource,
                    "Microsoft.Storage/storageAccounts"))
            .ToList();

        if (storageAccounts.Count == 0)
        {
            return;
        }

        var locations = storageAccounts
            .Select(resource => resource.Location)
            .Where(
                location =>
                    !string.IsNullOrWhiteSpace(location))
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .ToList();

        // La correlazione ha senso solo se gli Storage Account
        // rilevati sono concentrati in una singola region.
        if (locations.Count != 1)
        {
            return;
        }

        var lrsStorageAccounts =
            storageAccounts
                .Where(IsLrs)
                .ToList();

        if (lrsStorageAccounts.Count == 0)
        {
            return;
        }

        var storageNames =
            string.Join(
                ", ",
                lrsStorageAccounts
                    .Select(storage => storage.Name)
                    .Where(
                        name =>
                            !string.IsNullOrWhiteSpace(name))
                    .OrderBy(
                        name => name,
                        StringComparer.OrdinalIgnoreCase));

        var region =
            locations[0];

        findings.Add(
            new Finding(
                Id:
                    $"CORR-STORAGE-SINGLE-REGION-LRS-{subscription.Id}",
                Category:
                    Category.Reliability,
                Severity:
                    Severity.Medium,
                RuleId:
                    "CORR-STORAGE-SINGLE-REGION-LRS",
                Title:
                    "Storage con LRS concentrato in una singola region",
                Description:
                    $"L'ambiente contiene {lrsStorageAccounts.Count} " +
                    "Storage Account con LRS concentrati nella region " +
                    $"'{region}'. Risorse coinvolte: {storageNames}.",
                Impact:
                    "La combinazione di una singola region e replica LRS " +
                    "non fornisce ridondanza geografica e può limitare " +
                    "le opzioni di disaster recovery in caso di " +
                    "indisponibilità della region.",
                Recommendation:
                    "Verificare i requisiti di RPO, RTO e disaster recovery " +
                    "del workload. Valutare ZRS, GRS o GZRS in funzione " +
                    "dei requisiti, dei costi e delle funzionalità supportate.",
                ResourceName:
                    subscription.Name,
                ResourceType:
                    "Microsoft.Resources/subscriptions",
                ResourceId:
                    subscription.Id));
    }

    private static bool HasManagementExposure(
        AzureResource nsg)
    {
        var properties =
            nsg.GetEffectiveProperties();

        if (!properties.HasValue ||
            !properties.Value.TryGetProperty(
                "securityRules",
                out var rules) ||
            rules.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var rule in rules.EnumerateArray())
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

            if (destinationPort is
                "22" or
                "3389" or
                "*" or
                "0-65535")
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
                    string.Equals(
                        relationship.RelationshipType,
                        relationshipType,
                        StringComparison.OrdinalIgnoreCase))
            .Select(
                relationship =>
                    FindResource(
                        resourcesById,
                        relationship.TargetResourceId))
            .OfType<AzureResource>();
    }

    private static IEnumerable<AzureResource> GetTargetsThroughSubnet(
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
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

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

        var sku =
            resource.Sku.Value;

        if (!sku.TryGetProperty(
                "name",
                out var name) ||
            name.ValueKind !=
                JsonValueKind.String)
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
            zones.ValueKind ==
                JsonValueKind.Array &&
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

    private static bool TryGetBool(
        JsonElement element,
        string propertyName,
        out bool value)
    {
        if (!element.TryGetProperty(
                propertyName,
                out var property))
        {
            value = false;
            return false;
        }

        switch (property.ValueKind)
        {
            case JsonValueKind.True:
                value = true;
                return true;

            case JsonValueKind.False:
                value = false;
                return true;

            default:
                value = false;
                return false;
        }
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

    private static string? GetString(
        JsonElement element,
        string propertyName)
    {
        if (!element.TryGetProperty(
                propertyName,
                out var value) ||
            value.ValueKind !=
                JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }
}