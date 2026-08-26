using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class OperationsAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
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
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var untagged =
            resources
                .Where(
                    r =>
                        !HasTags(r))
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
                    "Microsoft.Resources/subscriptions"));
    }

    // =========================================================
    // LOCATION
    // =========================================================

    private static void AnalyzeMissingLocation(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var invalid =
            resources.Count(
                r =>
                {
                    var location =
                        GetString(
                            r,
                            "location");

                    return string.IsNullOrWhiteSpace(
                        location);
                });

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
                    "Microsoft.Resources/subscriptions"));
    }

    // =========================================================
    // HELPERS
    // =========================================================

    private static bool HasTags(
        JsonElement resource)
    {
        if (!resource.TryGetProperty(
                "tags",
                out var tags))
        {
            return false;
        }

        if (tags.ValueKind !=
            JsonValueKind.Object)
        {
            return false;
        }

        return tags.EnumerateObject().Any();
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            && value.ValueKind ==
                JsonValueKind.String
            ? value.GetString()
            : null;
    }
}