using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class OperationsAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        if (resources == null)
            throw new ArgumentNullException(nameof(resources));

        if (subscription == null)
            throw new ArgumentNullException(nameof(subscription));

        var findings =
            new List<Finding>();

        AnalyzeMissingTags(
            resources,
            subscription,
            findings);

        AnalyzeMissingLocation(
            resources,
            subscription,
            findings);

        AnalyzeVmBackupProtection(
            resources,
            findings);

        return findings;
    }

    // =========================================================
    // TAGGING
    // =========================================================

    private static void AnalyzeMissingTags(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var untagged =
            resources
                .Where(
                    resource =>
                        resource.Tags.Count == 0)
                .ToList();

        if (untagged.Count == 0)
        {
            return;
        }

        findings.Add(
            new Finding(
                Id:
                    Guid.NewGuid().ToString(),

                Category:
                    Category.Operations,

                Severity:
                    Severity.Medium,

                RuleId:
                    "GOV-NO-TAGS",

                Title:
                    $"{untagged.Count} risorse prive di tag",

                Description:
                    $"{untagged.Count} risorse su {resources.Count} " +
                    "non hanno tag di governance.",

                Impact:
                    "Riduce la capacità di attribuire costi, " +
                    "ownership e ambiente.",

                Recommendation:
                    "Definire uno standard di tagging e applicarlo " +
                    "tramite Azure Policy.",

                ResourceName:
                    subscription.Name,

                ResourceType:
                    "Microsoft.Resources/subscriptions",

                ResourceId:
                    subscription.Id));
    }

    // =========================================================
    // LOCATION
    // =========================================================

    private static void AnalyzeMissingLocation(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var invalid =
            resources.Count(
                resource =>
                    string.IsNullOrWhiteSpace(
                        resource.Location));

        if (invalid == 0)
        {
            return;
        }

        findings.Add(
            new Finding(
                Id:
                    Guid.NewGuid().ToString(),

                Category:
                    Category.Operations,

                Severity:
                    Severity.Low,

                RuleId:
                    "GOV-NO-LOCATION",

                Title:
                    $"{invalid} risorse senza location",

                Description:
                    $"{invalid} risorse non espongono una " +
                    "location valida nella discovery.",

                Impact:
                    "Può complicare governance, inventory e " +
                    "analisi geografica dell'ambiente.",

                Recommendation:
                    "Verificare la risorsa e la modalità con cui " +
                    "viene esposta da Azure Resource Manager.",

                ResourceName:
                    subscription.Name,

                ResourceType:
                    "Microsoft.Resources/subscriptions",

                ResourceId:
                    subscription.Id));
    }

    // =========================================================
    // AZURE BACKUP
    // =========================================================

    private static void AnalyzeVmBackupProtection(
        IReadOnlyList<AzureResource> resources,
        List<Finding> findings)
    {
        var virtualMachines =
            resources.Where(
                resource =>
                    IsType(
                        resource,
                        "Microsoft.Compute/virtualMachines"));

        foreach (var vm in virtualMachines)
        {
            var properties =
                vm.GetEffectiveProperties();

            if (!properties.HasValue)
            {
                continue;
            }

            /*
             * AzureResourceClient arricchisce le properties
             * della VM con il valore interno:
             *
             * cloudLensBackupProtected
             *
             * Il valore viene ricavato da Azure Resource Graph
             * correlando la VM con:
             *
             * RecoveryServicesResources
             *   -> protectedItems
             *   -> properties.sourceResourceId
             *
             * Non utilizziamo quindi:
             * - presenza di un Recovery Services Vault
             * - nome della VM
             * - nome del Protected Item
             * - semplici relazioni infrastrutturali
             */

            var backupProtected =
                GetBool(
                    properties.Value,
                    "cloudLensBackupProtected",
                    false);

            if (backupProtected)
            {
                continue;
            }

            Add(
                findings,
                vm,
                "OPS-VM-NO-BACKUP",
                Severity.Medium,
                "VM senza protezione Azure Backup rilevata",
                "La VM non risulta associata a un Protected Item Azure Backup per la relativa risorsa.",
                "La VM potrebbe non essere protetta da un processo di backup Azure configurato.",
                "Verificare i requisiti di protezione della VM e configurare Azure Backup tramite una policy appropriata se necessario.");
        }
    }

    // =========================================================
    // HELPERS
    // =========================================================

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

    private static void Add(
        List<Finding> findings,
        AzureResource resource,
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
                    Category.Operations,

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