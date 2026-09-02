using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class OperationsAnalyzer : IAnalyzer
{
public IEnumerable<Finding> Analyze(
IReadOnlyList<AzureResource> resources,
AzureSubscription subscription)
{
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
}
