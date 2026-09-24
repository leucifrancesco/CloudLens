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
        {
            throw new ArgumentNullException(nameof(resources));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(nameof(subscription));
        }

        var findings = new List<Finding>();

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
                    $"GOV-NO-TAGS-{subscription.Id}",

                Category:
                    Category.Governance,

                Severity:
                    Severity.Medium,

                RuleId:
                    "GOV-NO-TAGS",

                Title:
                    $"{untagged.Count} risorse prive di tag",

                Description:
                    $"{untagged.Count} risorse su {resources.Count} " +
                    "non espongono tag nella discovery effettuata.",

                Impact:
                    "L'assenza di una strategia di tagging può " +
                    "limitare l'attribuzione dei costi, " +
                    "l'identificazione dell'ownership e la distinzione " +
                    "tra ambienti e workload.",

                Recommendation:
                    "Verificare i requisiti di governance del tenant " +
                    "e definire uno standard di tagging coerente con " +
                    "le esigenze dell'organizzazione. Se appropriato, " +
                    "applicare e controllare lo standard tramite " +
                    "Azure Policy.",

                ResourceName:
                    subscription.Name,

                ResourceType:
                    "Microsoft.Resources/subscriptions",

                ResourceId:
                    subscription.Id));
    }

    // =========================================================
    // LOCATION / DISCOVERY QUALITY
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
                    $"GOV-NO-LOCATION-{subscription.Id}",

                Category:
                    Category.Governance,

                Severity:
                    Severity.Low,

                RuleId:
                    "GOV-NO-LOCATION",

                Title:
                    $"{invalid} risorse senza location",

                Description:
                    $"{invalid} risorse non espongono una " +
                    "location valida nei dati raccolti " +
                    "durante la discovery.",

                Impact:
                    "I dati incompleti possono ridurre l'affidabilità " +
                    "dell'inventory e delle analisi basate sulla " +
                    "distribuzione geografica delle risorse.",

                Recommendation:
                    "Verificare se l'assenza della location dipende " +
                    "dal tipo di risorsa o dalla modalità di discovery. " +
                    "Non considerare automaticamente la risorsa " +
                    "non conforme.",

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
             * della VM con:
             *
             * cloudLensBackupProtected
             *
             * Il valore viene ricavato da Azure Resource Graph
             * correlando la VM con RecoveryServicesResources
             * / protectedItems / properties.sourceResourceId.
             *
             * IMPORTANTE:
             * l'assenza della proprietà non viene interpretata
             * come "backup assente". In quel caso il dato di
             * enrichment non è disponibile e il finding viene
             * omesso per evitare falsi positivi.
             */

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

            Add(
                findings,
                vm,
                "OPS-VM-NO-BACKUP",
                Severity.Medium,
                "VM senza protezione Azure Backup rilevata",
                "La VM non risulta associata a un Protected Item " +
                "Azure Backup nei dati di enrichment raccolti.",
                "La VM potrebbe non essere protetta da un processo " +
                "di backup Azure configurato.",
                "Verificare i requisiti di protezione della VM e, " +
                "se necessario, configurare Azure Backup tramite " +
                "una policy appropriata.");
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

    private static bool TryGetBool(
        JsonElement element,
        string name,
        out bool value)
    {
        if (!element.TryGetProperty(
                name,
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