using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class AssessmentEngine
{
    private readonly IReadOnlyList<IAnalyzer> _analyzers;
    private readonly MetricAnalyzer _metricAnalyzer;

    public AssessmentEngine(
        IEnumerable<IAnalyzer> analyzers)
    {
        if (analyzers == null)
        {
            throw new ArgumentNullException(nameof(analyzers));
        }

        _analyzers = analyzers
            .Where(analyzer => analyzer != null)
            .ToList();

        if (_analyzers.Count == 0)
        {
            throw new ArgumentException(
                "È necessario registrare almeno un analyzer.",
                nameof(analyzers));
        }

        _metricAnalyzer = new MetricAnalyzer();
    }

    public ScanResult Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        return Analyze(
            resources,
            subscription,
            []);
    }

    public ScanResult Analyze(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription,
        IReadOnlyList<MetricProfile> metrics)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(nameof(resources));
        }

        if (subscription == null)
        {
            throw new ArgumentNullException(nameof(subscription));
        }

        if (metrics == null)
        {
            throw new ArgumentNullException(nameof(metrics));
        }

        var findings = CollectFindings(
            resources,
            subscription);

        if (metrics.Count > 0)
        {
            findings.AddRange(
                _metricAnalyzer.Analyze(
                    resources,
                    metrics,
                    subscription));
        }

        var normalizedFindings =
            NormalizeFindings(findings);

        normalizedFindings =
            ApplyCorrelationSuppression(
                normalizedFindings);

        var stats =
            BuildStats(resources);

        var scores =
            ComputeScores(normalizedFindings);

        var overallScore =
            CalculateOverallScore(scores);

        return new ScanResult
        {
            SubscriptionName = subscription.Name,
            SubscriptionId = subscription.Id,
            Stats = stats,
            Findings = normalizedFindings,
            ScoresByCategory = scores,
            Score = overallScore,
            MetricProfiles = metrics.ToList()
        };
    }

    private List<Finding> CollectFindings(
        IReadOnlyList<AzureResource> resources,
        AzureSubscription subscription)
    {
        var findings = new List<Finding>();

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

            findings.AddRange(analyzerFindings);
        }

        return findings;
    }

    private static List<Finding> NormalizeFindings(
        IEnumerable<Finding> findings)
    {
        return findings
            .Where(finding => finding != null)
            .GroupBy(
                GetFindingKey,
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(
                finding => GetSeverityOrder(finding.Severity))
            .ThenBy(finding => finding.Category)
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

    private static List<Finding>
        ApplyCorrelationSuppression(
            IReadOnlyList<Finding> findings)
    {
        var result = findings.ToList();

        // =====================================================
        // VM: BACKUP + HA
        // =====================================================

        var correlatedVmIds =
            result
                .Where(
                    finding =>
                        finding.RuleId ==
                        "CORR-VM-NO-BACKUP-NO-HA")
                .Select(
                    finding =>
                        finding.ResourceId)
                .Where(
                    resourceId =>
                        !string.IsNullOrWhiteSpace(resourceId))
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        if (correlatedVmIds.Count > 0)
        {
            result = result
                .Where(
                    finding =>
                    {
                        if (!correlatedVmIds.Contains(
                                finding.ResourceId ??
                                string.Empty))
                        {
                            return true;
                        }

                        return
                            finding.RuleId !=
                                "OPS-VM-NO-BACKUP" &&
                            finding.RuleId !=
                                "VM-NO-HA-DOMAIN" &&
                            finding.RuleId !=
                                "ARCH-VM-NO-HA-DOMAIN";
                    })
                .ToList();
        }

        // =====================================================
        // STORAGE: LRS + SINGLE REGION
        // =====================================================

        var correlatedStorageIds =
            result
                .Where(
                    finding =>
                        finding.RuleId ==
                        "CORR-STORAGE-SINGLE-REGION-LRS")
                .Select(
                    finding =>
                        finding.ResourceId)
                .Where(
                    resourceId =>
                        !string.IsNullOrWhiteSpace(resourceId))
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        if (correlatedStorageIds.Count > 0)
        {
            result = result
                .Where(
                    finding =>
                    {
                        if (!correlatedStorageIds.Contains(
                                finding.ResourceId ??
                                string.Empty))
                        {
                            return true;
                        }

                        return
                            finding.RuleId !=
                                "ST-LRS-REPLICATION" &&
                            finding.RuleId !=
                                "ARCH-STORAGE-LRS";
                    })
                .ToList();
        }

        return result;
    }

    private static string GetFindingKey(
        Finding finding)
    {
        var resourceKey =
            !string.IsNullOrWhiteSpace(finding.ResourceId)
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

    private static ScanStats BuildStats(
        IReadOnlyList<AzureResource> resources)
    {
        return new ScanStats
        {
            Resources = resources.Count,

            Vms = resources.Count(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Compute/virtualMachines")),

            Disks = resources.Count(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Compute/disks")),

            Nsgs = resources.Count(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Network/networkSecurityGroups")),

            PublicIps = resources.Count(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Network/publicIPAddresses")),

            StorageAccounts = resources.Count(
                resource =>
                    TypeEquals(
                        resource,
                        "Microsoft.Storage/storageAccounts")),

            Advisor = 0,

            MonthlyCostEur = 0
        };
    }

    private static Dictionary<Category, int> ComputeScores(
        IReadOnlyList<Finding> findings)
    {
        var result =
            new Dictionary<Category, int>();

        foreach (var category in
                 Enum.GetValues<Category>())
        {
            var categoryFindings =
                findings
                    .Where(
                        finding =>
                            finding.Category == category)
                    .ToList();

            var penalty =
                CalculateCategoryPenalty(
                    categoryFindings);

            result[category] =
                Math.Max(
                    0,
                    100 - penalty);
        }

        return result;
    }

    private static int CalculateCategoryPenalty(
        IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            return 0;
        }

        var totalPenalty = 0.0;

        var resourceGroups =
            findings
                .GroupBy(
                    GetResourceRiskKey,
                    StringComparer.OrdinalIgnoreCase);

        foreach (var resourceGroup in resourceGroups)
        {
            var penalties =
                resourceGroup
                    .Select(
                        finding =>
                            GetSeverityPenalty(
                                finding.Severity))
                    .OrderByDescending(
                        penalty => penalty)
                    .ToList();

            for (var index = 0;
                 index < penalties.Count;
                 index++)
            {
                var multiplier =
                    index switch
                    {
                        0 => 1.00,
                        1 => 0.60,
                        2 => 0.40,
                        _ => 0.25
                    };

                totalPenalty +=
                    penalties[index] *
                    multiplier;
            }
        }

        return (int)Math.Round(
            Math.Min(
                100,
                totalPenalty));
    }

    private static string GetResourceRiskKey(
        Finding finding)
    {
        if (!string.IsNullOrWhiteSpace(
                finding.ResourceId))
        {
            return finding.ResourceId!;
        }

        return
            $"{finding.ResourceType}|{finding.ResourceName}";
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
