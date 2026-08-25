using System.Text.Json;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class AssessmentEngine
{
    private readonly IReadOnlyList<IAnalyzer> _analyzers;

    public AssessmentEngine(
        IEnumerable<IAnalyzer> analyzers)
    {
        _analyzers =
            analyzers?.ToList()
            ?? throw new ArgumentNullException(
                nameof(analyzers));

        if (_analyzers.Count == 0)
        {
            throw new ArgumentException(
                "È necessario registrare almeno un analyzer.",
                nameof(analyzers));
        }
    }


    // =========================================================
    // ASSESSMENT
    // =========================================================

    public ScanResult Analyze(
        IReadOnlyList<JsonElement> resources,
        AzureSubscription subscription)
    {
        if (resources == null)
            throw new ArgumentNullException(
                nameof(resources));

        if (subscription == null)
            throw new ArgumentNullException(
                nameof(subscription));

        var findings =
            new List<Finding>();


        // -----------------------------------------------------
        // ESECUZIONE ANALYZER
        // -----------------------------------------------------

        foreach (var analyzer in _analyzers)
        {
            var analyzerFindings =
                analyzer.Analyze(
                    resources,
                    subscription);

            if (analyzerFindings == null)
                continue;

            findings.AddRange(
                analyzerFindings);
        }


        // -----------------------------------------------------
        // STATISTICHE RISORSE
        // -----------------------------------------------------

        var stats =
            BuildStats(resources);


        // -----------------------------------------------------
        // SCORE
        // -----------------------------------------------------

        var scores =
            ComputeScores(findings);


        var overallScore =
            scores.Count == 0
                ? 100
                : (int)Math.Round(
                    scores.Values.Average());


        // -----------------------------------------------------
        // RESULT
        // -----------------------------------------------------

        return new ScanResult
        {
            SubscriptionName =
                subscription.Name,

            SubscriptionId =
                subscription.Id,

            Stats =
                stats,

            Findings =
                findings,

            ScoresByCategory =
                scores,

            Score =
                overallScore
        };
    }


    // =========================================================
    // RESOURCE STATISTICS
    // =========================================================

    private static ScanStats BuildStats(
        IReadOnlyList<JsonElement> resources)
    {
        return new ScanStats
        {
            Resources =
                resources.Count,

            Vms =
                resources.Count(
                    r => TypeEquals(
                        r,
                        "Microsoft.Compute/virtualMachines")),

            Disks =
                resources.Count(
                    r => TypeEquals(
                        r,
                        "Microsoft.Compute/disks")),

            Nsgs =
                resources.Count(
                    r => TypeEquals(
                        r,
                        "Microsoft.Network/networkSecurityGroups")),

            PublicIps =
                resources.Count(
                    r => TypeEquals(
                        r,
                        "Microsoft.Network/publicIPAddresses")),

            StorageAccounts =
                resources.Count(
                    r => TypeEquals(
                        r,
                        "Microsoft.Storage/storageAccounts"))
        };
    }


    // =========================================================
    // SCORE
    // =========================================================

    private static Dictionary<Category, int> ComputeScores(
        IReadOnlyList<Finding> findings)
    {
        var result =
            new Dictionary<Category, int>();

        foreach (var category in
                 Enum.GetValues<Category>())
        {
            var penalty =
                findings
                    .Where(f =>
                        f.Category == category)
                    .Sum(
                        f =>
                            f.Severity switch
                            {
                                Severity.Critical => 25,
                                Severity.High => 15,
                                Severity.Medium => 7,
                                Severity.Low => 3,
                                _ => 0
                            });

            result[category] =
                Math.Max(
                    0,
                    100 - penalty);
        }

        return result;
    }


    // =========================================================
    // HELPERS
    // =========================================================

    private static bool TypeEquals(
        JsonElement resource,
        string type)
    {
        return resource.TryGetProperty(
                   "type",
                   out var typeElement)
               &&
               string.Equals(
                   typeElement.GetString(),
                   type,
                   StringComparison.OrdinalIgnoreCase);
    }
}