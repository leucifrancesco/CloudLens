using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class AssessmentEngine
{
    private readonly IReadOnlyList<IAnalyzer> _analyzers;

    public AssessmentEngine(
        IEnumerable<IAnalyzer> analyzers)
    {
        if (analyzers == null)
        {
            throw new ArgumentNullException(
                nameof(analyzers));
        }

        _analyzers =
            analyzers
                .Where(
                    analyzer => analyzer != null)
                .ToList();

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

        // -----------------------------------------------------
        // 1. EXECUTE ANALYZERS
        // -----------------------------------------------------

        var findings =
            CollectFindings(
                resources,
                subscription);

        // -----------------------------------------------------
        // 2. NORMALIZE FINDINGS
        // -----------------------------------------------------

        var normalizedFindings =
            NormalizeFindings(
                findings);

        // -----------------------------------------------------
        // 3. BUILD RESOURCE STATISTICS
        // -----------------------------------------------------

        var stats =
            BuildStats(
                resources);

        // -----------------------------------------------------
        // 4. CALCULATE CATEGORY SCORES
        // -----------------------------------------------------

        var scores =
            ComputeScores(
                normalizedFindings);

        // -----------------------------------------------------
        // 5. CALCULATE OVERALL SCORE
        // -----------------------------------------------------

        var overallScore =
            CalculateOverallScore(
                scores);

        // -----------------------------------------------------
        // 6. BUILD RESULT
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
                normalizedFindings,

            ScoresByCategory =
                scores,

            Score =
                overallScore
        };
    }

    // =========================================================
    // ANALYZER EXECUTION
    // =========================================================

    private List<Finding> CollectFindings(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
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

        return findings;
    }

    // =========================================================
    // FINDING NORMALIZATION
    // =========================================================

    private static List<Finding> NormalizeFindings(
        IEnumerable<Finding> findings)
    {
        return findings
            .Where(
                finding => finding != null)
            .GroupBy(
                GetFindingKey,
                StringComparer.OrdinalIgnoreCase)
            .Select(
                group => group.First())
            .OrderBy(
                finding => GetSeverityOrder(
                    finding.Severity))
            .ThenBy(
                finding => finding.Category)
            .ThenBy(
                finding => finding.ResourceType,
                StringComparer.OrdinalIgnoreCase)
            .ThenBy(
                finding => finding.ResourceName,
                StringComparer.OrdinalIgnoreCase)
            .ThenBy(
                finding => finding.RuleId,
                StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string GetFindingKey(
        Finding finding)
    {
        var resourceKey =
            !string.IsNullOrWhiteSpace(
                finding.ResourceId)
                ? finding.ResourceId
                : finding.ResourceName;

        return
            $"{finding.RuleId}|{resourceKey}";
    }

    private static int GetSeverityOrder(
        Severity severity)
    {
        return severity switch
        {
            Severity.Critical => 0,
            Severity.High => 1,
            Severity.Medium => 2,
            Severity.Low => 3,
            _ => 4
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
                    resource => TypeEquals(
                        resource,
                        "Microsoft.Compute/virtualMachines")),

            Disks =
                resources.Count(
                    resource => TypeEquals(
                        resource,
                        "Microsoft.Compute/disks")),

            Nsgs =
                resources.Count(
                    resource => TypeEquals(
                        resource,
                        "Microsoft.Network/networkSecurityGroups")),

            PublicIps =
                resources.Count(
                    resource => TypeEquals(
                        resource,
                        "Microsoft.Network/publicIPAddresses")),

            StorageAccounts =
                resources.Count(
                    resource => TypeEquals(
                        resource,
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
                        finding =>
                            finding.Category == category)
                    .Sum(
                        finding =>
                            GetSeverityPenalty(
                                finding.Severity));

            result[category] =
                Math.Max(
                    0,
                    100 - penalty);
        }

        return result;
    }

    private static int GetSeverityPenalty(
        Severity severity)
    {
        return severity switch
        {
            Severity.Critical => 25,
            Severity.High => 15,
            Severity.Medium => 7,
            Severity.Low => 3,
            _ => 0
        };
    }

    private static int CalculateOverallScore(
        IReadOnlyDictionary<Category, int> scores)
    {
        if (scores.Count == 0)
        {
            return 100;
        }

        return (int)Math.Round(
            scores.Values.Average());
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