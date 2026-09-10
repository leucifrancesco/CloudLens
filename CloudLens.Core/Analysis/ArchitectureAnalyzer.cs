using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ArchitectureAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeVirtualMachines(
            resources,
            findings);

        AnalyzeVirtualMachineScaleSets(
            resources,
            findings);

        AnalyzeStorageReplication(
            resources,
            findings);

        AnalyzeBasicResourceDistribution(
            resources,
            subscription,
            findings);

        return findings;
    }

    private static void AnalyzeVirtualMachines(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var vms =
            resources.Where(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Compute/virtualMachines"));

        foreach (var vm in vms)
        {
            var properties =
                vm.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var hasAvailabilityZone =
                HasAvailabilityZone(
                    properties.Value);

            var hasAvailabilitySet =
                HasAvailabilitySet(
                    properties.Value);

            if (hasAvailabilityZone ||
                hasAvailabilitySet)
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "VM-NO-HA-DOMAIN",

                    Title:
                        "VM senza Availability Zone o Availability Set",

                    Description:
                        $"La VM '{vm.Name}' non risulta associata " +
                        "ad una Availability Zone o ad un Availability Set.",

                    Impact:
                        "La VM può rimanere maggiormente dipendente " +
                        "da un singolo failure domain della region.",

                    Recommendation:
                        "Valutare Availability Zone o Availability Set " +
                        "in funzione dei requisiti di disponibilità " +
                        "e della regione utilizzata.",

                    ResourceName:
                        vm.Name,

                    ResourceType:
                        vm.Type,

                    ResourceId:
                        vm.Id));
        }
    }

    private static void AnalyzeVirtualMachineScaleSets(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var scaleSets =
            resources.Where(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Compute/virtualMachineScaleSets"));

        foreach (var scaleSet in scaleSets)
        {
            var properties =
                scaleSet.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            var zones =
                GetArray(
                    properties.Value,
                    "zones");

            var hasAvailabilityZone =
                zones.HasValue &&
                zones.Value.ValueKind ==
                    JsonValueKind.Array &&
                zones.Value.GetArrayLength() > 0;

            if (!hasAvailabilityZone)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Reliability,

                        Severity:
                            Severity.Low,

                        RuleId:
                            "VMSS-NO-ZONE",

                        Title:
                            "VM Scale Set senza Availability Zone configurata",

                        Description:
                            $"Il VM Scale Set '{scaleSet.Name}' " +
                            "non risulta associato ad Availability Zone.",

                        Impact:
                            "Le istanze possono rimanere concentrate " +
                            "in un singolo failure domain.",

                        Recommendation:
                            "Valutare una configurazione zonale " +
                            "quando supportata dalla workload architecture.",

                        ResourceName:
                            scaleSet.Name,

                        ResourceType:
                            scaleSet.Type,

                        ResourceId:
                            scaleSet.Id));
            }

            var sku =
                scaleSet.Sku;

            if (!sku.HasValue)
            {
                continue;
            }

            if (!sku.Value.TryGetProperty(
                    "capacity",
                    out var capacity))
            {
                continue;
            }

            if (!capacity.TryGetInt32(
                    out var instanceCount))
            {
                continue;
            }

            if (instanceCount <= 1)
            {
                findings.Add(
                    new Finding(
                        Id:
                            Guid.NewGuid().ToString(),

                        Category:
                            Category.Reliability,

                        Severity:
                            Severity.Medium,

                        RuleId:
                            "VMSS-SINGLE-INSTANCE",

                        Title:
                            "VM Scale Set con una sola istanza",

                        Description:
                            $"Il VM Scale Set '{scaleSet.Name}' " +
                            "risulta configurato con una sola istanza.",

                        Impact:
                            "La perdita della singola istanza può " +
                            "causare indisponibilità del workload.",

                        Recommendation:
                            "Valutare almeno due istanze quando " +
                            "il requisito applicativo richiede alta disponibilità.",

                        ResourceName:
                            scaleSet.Name,

                        ResourceType:
                            scaleSet.Type,

                        ResourceId:
                            scaleSet.Id));
            }
        }
    }

    private static void AnalyzeStorageReplication(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var storageAccounts =
            resources.Where(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Storage/storageAccounts"));

        foreach (var storage in storageAccounts)
        {
            if (storage.Sku is not JsonElement sku)
            {
                continue;
            }

            if (!sku.TryGetProperty(
                    "name",
                    out var skuNameElement) ||
                skuNameElement.ValueKind !=
                    JsonValueKind.String)
            {
                continue;
            }

            var skuName =
                skuNameElement.GetString();

            if (string.IsNullOrWhiteSpace(
                    skuName))
            {
                continue;
            }

            if (!skuName.Contains(
                    "LRS",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            findings.Add(
                new Finding(
                    Id:
                        Guid.NewGuid().ToString(),

                    Category:
                        Category.Reliability,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "ST-LRS-REPLICATION",

                    Title:
                        "Storage Account con replica LRS",

                    Description:
                        $"Lo Storage Account '{storage.Name}' " +
                        "utilizza una replica LRS.",

                    Impact:
                        "LRS offre una resilienza inferiore rispetto " +
                        "a configurazioni con ridondanza zonale o geografica.",

                    Recommendation:
                        "Valutare ZRS, GRS o GZRS in funzione dei " +
                        "requisiti di disponibilità e disaster recovery.",

                    ResourceName:
                        storage.Name,

                    ResourceType:
                        storage.Type,

                    ResourceId:
                        storage.Id));
        }
    }

    private static void AnalyzeBasicResourceDistribution(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        if (resources.Count == 0)
        {
            return;
        }

        var locations =
            resources
                .Select(
                    resource =>
                        resource.Location)
                .Where(
                    location =>
                        !string.IsNullOrWhiteSpace(location))
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        if (locations.Count != 1)
        {
            return;
        }

        findings.Add(
            new Finding(
                Id:
                    Guid.NewGuid().ToString(),

                Category:
                    Category.Reliability,

                Severity:
                    Severity.Low,

                RuleId:
                    "ARCH-SINGLE-REGION",

                Title:
                    "Ambiente distribuito in una sola region",

                Description:
                    $"Le risorse analizzate risultano concentrate " +
                    $"nella region '{locations[0]}'.",

                Impact:
                    "Un singolo failure domain geografico può " +
                    "aumentare il rischio di indisponibilità.",

                Recommendation:
                    "Valutare una strategia multi-region quando " +
                    "i requisiti applicativi lo rendono necessario.",

                ResourceName:
                    subscription.Name,

                ResourceType:
                    "Microsoft.Resources/subscriptions",

                ResourceId:
                    subscription.Id));
    }

    private static bool HasAvailabilityZone(
        JsonElement properties)
    {
        var zones =
            GetArray(
                properties,
                "zones");

        return zones.HasValue &&
               zones.Value.ValueKind ==
                   JsonValueKind.Array &&
               zones.Value.GetArrayLength() > 0;
    }

    private static bool HasAvailabilitySet(
        JsonElement properties)
    {
        if (!properties.TryGetProperty(
                "availabilitySet",
                out var availabilitySet))
        {
            return false;
        }

        if (availabilitySet.ValueKind !=
            JsonValueKind.Object)
        {
            return false;
        }

        if (!availabilitySet.TryGetProperty(
                "id",
                out var id))
        {
            return false;
        }

        return id.ValueKind ==
                   JsonValueKind.String &&
               !string.IsNullOrWhiteSpace(
                   id.GetString());
    }

    private static bool TypeEquals(
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }

    private static JsonElement? GetArray(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
                out var value))
        {
            return null;
        }

        return value;
    }
}