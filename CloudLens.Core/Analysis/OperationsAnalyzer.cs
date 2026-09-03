using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class OperationsAnalyzer : IAnalyzer
{
    public IEnumerable<Finding> Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

        AnalyzeMissingTags(
            resources,
            subscription,
            findings);

        return findings;
    }

    // ============================================================
    // TAG GOVERNANCE
    // ============================================================

    private static void AnalyzeMissingTags(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        List<Finding> findings)
    {
        var untaggedResources =
            resources
                .Where(resource => resource.Tags.Count == 0)
                .ToList();

        if (untaggedResources.Count == 0)
            return;

        var percentage =
            resources.Count == 0
                ? 0
                : (double)untaggedResources.Count /
                  resources.Count *
                  100;

        var percentageText =
            percentage.ToString(
                "0.#",
                System.Globalization.CultureInfo.InvariantCulture);

        findings.Add(
            new Finding(
                Id: Guid.NewGuid().ToString(),
                Category: Category.Operations,
                Severity: Severity.Medium,
                RuleId: "GOV-NO-TAGS",
                Title:
                    $"{untaggedResources.Count} risorse prive di tag",
                Description:
                    $"{untaggedResources.Count} risorse su " +
                    $"{resources.Count} ({percentageText}%) " +
                    "non hanno tag di governance.",
                Impact:
                    "L'assenza di tag riduce la capacità di attribuire " +
                    "costi, ownership, ambiente e finalità delle risorse.",
                Recommendation:
                    "Definire uno standard di tagging per proprietà come " +
                    "Environment, Owner, CostCenter e Application e " +
                    "applicarlo tramite Azure Policy dove appropriato.",
                ResourceName: subscription.Name,
                ResourceType:
                    "Microsoft.Resources/subscriptions",
                ResourceId: subscription.Id));
    }
}