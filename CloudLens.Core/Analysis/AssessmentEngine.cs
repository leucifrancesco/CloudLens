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
    IReadOnlyList<AzureResource> resources,
    AzureSubscription subscription)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(
                nameof(resources));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(
                nameof(subscription));
        }

        var findings =
            new List<Finding>();

        foreach (var analyzer in _analyzers)
        {
            var analyzerFindings =
                analyzer.Analyze(
                    resources,
                    subscription);

            if (analyzerFindings == null)
            {
                continue;
            }

            findings.AddRange(
                analyzerFindings);
        }

        // Evita duplicati accidentali della stessa regola
        // sulla stessa risorsa.
        findings =
            findings
                .GroupBy(
                    f => new
                    {
                        f.RuleId,
                        f.ResourceId,
                        f.ResourceName
                    })
                .Select(
                    g => g.First())
                .ToList();

        var stats =
            BuildStats(resources);

        var scores =
            ComputeScores(findings);

        var overallScore =
            scores.Count == 0
                ? 100
                : (int)Math.Round(
                    scores.Values.Average());

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
    IReadOnlyList<AzureResource> resources)
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
                        "Microsoft.Storage/storageAccounts")),

            Advisor =
                0,

            MonthlyCostEur =
                0
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
                    .Where(
                        f => f.Category == category)
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
        AzureResource resource,
        string type)
    {
        return string.Equals(
            resource.Type,
            type,
            StringComparison.OrdinalIgnoreCase);
    }
}