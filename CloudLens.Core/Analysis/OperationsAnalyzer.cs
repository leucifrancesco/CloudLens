using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class OperationsAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeMissingTags(
            resources,
            subscription,
            findings);

        return findings;
    }


    // ---------------------------------------------------------
    // RISORSE SENZA TAG
    // ---------------------------------------------------------

    private static void AnalyzeMissingTags(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var untagged =
            resources.Count(
                r =>
                    !r.TryGetProperty(
                        "tags",
                        out var tags) ||
                    tags.ValueKind ==
                        JsonValueKind.Null ||
                    (
                        tags.ValueKind ==
                            JsonValueKind.Object &&
                        !tags.EnumerateObject().Any()
                    ));

        if (untagged <= 0)
            return;

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
                    $"{untagged} risorse prive di tag",

                Description:
                    $"{untagged} risorse su {resources.Count} " +
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
}