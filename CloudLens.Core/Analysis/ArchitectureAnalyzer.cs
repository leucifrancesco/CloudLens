using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class ArchitectureAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(nameof(resources));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(nameof(subscription));
        }

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

    // =========================================================
    // VIRTUAL MACHINES
    // =========================================================

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
                        $"ARCH-VM-NO-HA-DOMAIN-{vm.Id}",

                    Category:
                        Category.Architecture,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "ARCH-VM-NO-HA-DOMAIN",

                    Title:
                        "VM senza Availability Zone o Availability Set",

                    Description:
                        $"La VM '{vm.Name}' non risulta associata " +
                        "ad una Availability Zone o ad un Availability Set.",

                    Impact:
                        "La VM non dispone, a livello di configurazione " +
                        "rilevata, di una distribuzione esplicita tra " +
                        "failure domain tramite Availability Zone o " +
                        "Availability Set.",

                    Recommendation:
                        "Verificare i requisiti di disponibilità del " +
                        "workload. Se richiesto, valutare Availability " +
                        "Zone, Availability Set o un'architettura " +
                        "ridondata appropriata.",

                    ResourceName:
                        vm.Name,

                    ResourceType:
                        vm.Type,

                    ResourceId:
                        vm.Id));
        }
    }

    // =========================================================
    // VIRTUAL MACHINE SCALE SETS
    // =========================================================

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
                            $"ARCH-VMSS-NO-ZONE-{scaleSet.Id}",

                        Category:
                            Category.Architecture,

                        Severity:
                            Severity.Low,

                        RuleId:
                            "ARCH-VMSS-NO-ZONE",

                        Title:
                            "VM Scale Set senza Availability Zone configurata",

                        Description:
                            $"Il VM Scale Set '{scaleSet.Name}' " +
                            "non risulta associato ad Availability Zone.",

                        Impact:
                            "Le istanze del VM Scale Set non risultano " +
                            "esplicitamente distribuite tra Availability Zone.",

                        Recommendation:
                            "Verificare i requisiti di disponibilità " +
                            "del workload e valutare una configurazione " +
                            "zonale quando supportata e necessaria.",

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
                            $"ARCH-VMSS-SINGLE-INSTANCE-{scaleSet.Id}",

                        Category:
                            Category.Reliability,

                        Severity:
                            Severity.Medium,

                        RuleId:
                            "ARCH-VMSS-SINGLE-INSTANCE",

                        Title:
                            "VM Scale Set con una sola istanza",

                        Description:
                            $"Il VM Scale Set '{scaleSet.Name}' " +
                            "risulta configurato con una sola istanza.",

                        Impact:
                            "La perdita della singola istanza può " +
                            "causare indisponibilità del workload " +
                            "se non esistono altri meccanismi di ridondanza.",

                        Recommendation:
                            "Verificare i requisiti di disponibilità " +
                            "del workload. Se necessario, configurare " +
                            "più istanze e verificare il comportamento " +
                            "del workload durante il failover.",

                        ResourceName:
                            scaleSet.Name,

                        ResourceType:
                            scaleSet.Type,

                        ResourceId:
                            scaleSet.Id));
            }
        }
    }

    // =========================================================
    // STORAGE REPLICATION
    // =========================================================

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
                        $"ARCH-STORAGE-LRS-{storage.Id}",

                    Category:
                        Category.Architecture,

                    Severity:
                        Severity.Low,

                    RuleId:
                        "ARCH-STORAGE-LRS",

                    Title:
                        "Storage Account con replica LRS",

                    Description:
                        $"Lo Storage Account '{storage.Name}' " +
                        "utilizza una configurazione di replica LRS.",

                    Impact:
                        "LRS mantiene le copie dei dati all'interno " +
                        "dello stesso datacenter e non fornisce la " +
                        "stessa resilienza geografica o zonale di altre " +
                        "configurazioni di replica.",

                    Recommendation:
                        "Verificare i requisiti di resilienza, " +
                        "disaster recovery e data residency del workload. " +
                        "Se necessario, valutare ZRS, GRS o GZRS " +
                        "compatibilmente con il servizio e il workload.",

                    ResourceName:
                        storage.Name,

                    ResourceType:
                        storage.Type,

                    ResourceId:
                        storage.Id));
        }
    }

    // =========================================================
    // RESOURCE DISTRIBUTION
    // =========================================================

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
                    $"ARCH-SINGLE-REGION-{subscription.Id}",

                Category:
                    Category.Architecture,

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
                    "L'utilizzo di una sola region non fornisce " +
                    "ridondanza geografica tra region Azure.",

                Recommendation:
                    "Verificare i requisiti di continuità operativa, " +
                    "disaster recovery, latenza e data residency. " +
                    "Valutare una strategia multi-region solo quando " +
                    "richiesta dai requisiti del workload.",

                ResourceName:
                    subscription.Name,

                ResourceType:
                    "Microsoft.Resources/subscriptions",

                ResourceId:
                    subscription.Id));
    }

    // =========================================================
    // HELPERS
    // =========================================================

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