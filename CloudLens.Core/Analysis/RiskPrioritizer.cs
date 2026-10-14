using CloudLens.Core;

namespace CloudLens.Core.Analysis;

public sealed class RiskPrioritizer
{
    public AssessmentIntelligence Analyze(TenantScanResult assessment)
    {
        if (assessment == null)
        {
            throw new ArgumentNullException(nameof(assessment));
        }

        var findings = assessment.AllFindings
            .Where(finding => finding != null)
            .ToList();

        if (findings.Count == 0)
        {
            return new AssessmentIntelligence();
        }

        var normalizedFindings = findings
            .Select(NormalizeFindingCategory)
            .ToList();

        var ruleOccurrences = normalizedFindings
            .GroupBy(
                finding =>
                    $"{GetEffectiveCategory(finding)}|{finding.RuleId}",
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.ToList(),
                StringComparer.OrdinalIgnoreCase);

        var intelligenceRisks = normalizedFindings
            .Select(
                finding =>
                    BuildRisk(
                        finding,
                        ruleOccurrences))
            .OrderBy(risk => risk.Priority)
            .ThenByDescending(risk => risk.PriorityScore)
            .ThenBy(
                risk => SeverityOrder(risk.Severity))
            .ThenBy(
                risk => risk.Title,
                StringComparer.OrdinalIgnoreCase)
            .ToList();

        var systemicRisks =
            BuildSystemicRisks(ruleOccurrences);

        var systemicFindingIds =
            systemicRisks
                .SelectMany(risk => risk.FindingIds)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (systemicFindingIds.Count > 0)
        {
            intelligenceRisks =
                intelligenceRisks
                    .Select(
                        risk =>
                            systemicFindingIds.Contains(
                                risk.FindingId)
                                ? risk with
                                {
                                    IsSystemic = true,
                                    Classification =
                                        IntelligenceClassification
                                            .SystemicRisk
                                }
                                : risk)
                    .ToList();
        }

        var quickWins =
            intelligenceRisks
                .Where(risk => risk.IsQuickWin)
                .OrderBy(risk => risk.Priority)
                .ThenByDescending(
                    risk => risk.PriorityScore)
                .ThenBy(
                    risk => risk.EffortScore)
                .ToList();

        var roadmap =
            BuildRoadmap(
                intelligenceRisks,
                assessment);

        return new AssessmentIntelligence
        {
            Risks = intelligenceRisks,
            QuickWins = quickWins,
            SystemicRisks = systemicRisks,
            Roadmap = roadmap
        };
    }

    private static IntelligenceRisk BuildRisk(
        Finding finding,
        IReadOnlyDictionary<string, List<Finding>>
            ruleOccurrences)
    {
        var effectiveCategory =
            GetEffectiveCategory(finding);

        var severityScore =
            GetSeverityScore(finding.Severity);

        var impactScore =
            GetImpactScore(
                finding,
                effectiveCategory);

        var effortScore =
            GetEffortScore(finding);

        var exposureScore =
            GetExposureScore(
                finding,
                effectiveCategory);

        var scopeScore =
            GetScopeScore(
                finding,
                effectiveCategory,
                ruleOccurrences);

        var savingScore =
            GetSavingScore(
                finding.MonthlySavingEur);

        var riskTypeBonus =
            GetRiskTypeBonus(
                finding,
                effectiveCategory);

        var priorityScore =
            Math.Clamp(
                severityScore +
                impactScore +
                exposureScore +
                scopeScore +
                savingScore +
                riskTypeBonus -
                effortScore,
                0,
                100);

        var priority =
            GetPriority(
                finding.Severity,
                priorityScore,
                effectiveCategory,
                exposureScore);

        var isQuickWin =
            IsQuickWin(
                finding,
                priority,
                effortScore,
                effectiveCategory);

        var classification =
            GetClassification(
                finding,
                priority,
                isQuickWin,
                effectiveCategory);

        var rationale =
            BuildRationale(
                finding,
                effectiveCategory,
                priority,
                priorityScore,
                impactScore,
                effortScore,
                exposureScore,
                scopeScore,
                savingScore,
                isQuickWin);

        return new IntelligenceRisk(
            finding.Id,
            finding.RuleId,
            finding.Title,
            finding.ResourceName,
            finding.ResourceType,
            finding.ResourceId,
            effectiveCategory,
            finding.Severity,
            priority,
            classification,
            priorityScore,
            impactScore,
            effortScore,
            isQuickWin,
            false,
            finding.MonthlySavingEur,
            rationale);
    }

    private static List<SystemicRisk> BuildSystemicRisks(
        IReadOnlyDictionary<string, List<Finding>>
            ruleOccurrences)
    {
        return ruleOccurrences
            .Where(pair => pair.Value.Count >= 3)
            .Select(
                pair =>
                {
                    var findings = pair.Value;

                    // The representative finding must always be the
                    // highest-severity finding in the group.
                    // Do not rely on findings.First(), because the
                    // order of findings can change between subscriptions
                    // or discovery operations.
                    var representative =
                        findings
                            .OrderBy(
                                finding =>
                                    SeverityOrder(
                                        finding.Severity))
                            .First();

                    var effectiveCategory =
                        GetEffectiveCategory(
                            representative);

                    var affectedResources =
                        findings
                            .Select(
                                finding =>
                                    !string.IsNullOrWhiteSpace(
                                        finding.ResourceId)
                                        ? finding.ResourceId!
                                        : $"{finding.ResourceType}|{finding.ResourceName}")
                            .Distinct(
                                StringComparer.OrdinalIgnoreCase)
                            .Count();

                    var priorityScore =
                        Math.Clamp(
                            45 +
                            Math.Min(
                                25,
                                findings.Count * 5) +
                            GetSeverityScore(
                                representative.Severity) / 2 +
                            GetRiskTypeBonus(
                                representative,
                                effectiveCategory) / 2,
                            0,
                            100);

                    var priority =
                        representative.Severity switch
                        {
                            Severity.Critical =>
                                AssessmentPriority.P0,

                            Severity.High =>
                                AssessmentPriority.P1,

                            Severity.Medium
                                when findings.Count >= 5 =>
                                AssessmentPriority.P1,

                            _ =>
                                AssessmentPriority.P2
                        };

                    return new SystemicRisk(
                        $"SYS-{effectiveCategory}-{representative.RuleId}",
                        $"Systemic issue: {representative.Title}",
                        effectiveCategory,
                        representative.Severity,
                        findings.Count,
                        affectedResources,
                        priority,
                        priorityScore,
                        BuildSystemicDescription(
                            representative,
                            findings.Count,
                            affectedResources),
                        findings
                            .Select(finding => finding.Id)
                            .ToList());
                })
            .OrderBy(risk => risk.Priority)
            .ThenByDescending(
                risk => risk.PriorityScore)
            .ThenByDescending(
                risk => risk.FindingCount)
            .ToList();
    }

    private static List<RemediationRoadmapItem> BuildRoadmap(
        IReadOnlyList<IntelligenceRisk> risks,
        TenantScanResult assessment)
    {
        var remediationByFinding =
            assessment.Subscriptions
                .SelectMany(
                    subscription =>
                        subscription
                            .Result
                            .Remediation
                            .Actions)
                .GroupBy(
                    action => action.FindingId,
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group =>
                        group
                            .OrderBy(
                                action =>
                                    action.RequiresReview)
                            .First(),
                    StringComparer.OrdinalIgnoreCase);

        return risks
            .OrderBy(risk => risk.Priority)
            .ThenByDescending(
                risk => risk.PriorityScore)
            .ThenByDescending(
                risk => risk.MonthlySavingEur)
            .Select(
                risk =>
                {
                    remediationByFinding.TryGetValue(
                        risk.FindingId,
                        out var action);

                    return new RemediationRoadmapItem(
                        risk.FindingId,
                        risk.Title,
                        risk.Category,
                        risk.Severity,
                        risk.Priority,
                        risk.Classification,
                        risk.PriorityScore,
                        risk.ImpactScore,
                        risk.EffortScore,
                        risk.MonthlySavingEur,
                        action?.Action ??
                            "Review finding and implement the recommended remediation.",
                        action?.Command,
                        action?.RequiresReview ?? true);
                })
            .ToList();
    }

    private static Finding NormalizeFindingCategory(
        Finding finding)
    {
        var category = finding.Category;
        var ruleId = finding.RuleId ?? string.Empty;

        if (ruleId.StartsWith(
                "COST-",
                StringComparison.OrdinalIgnoreCase))
        {
            category = Category.Cost;
        }
        else if (
            ruleId.StartsWith(
                "SEC-",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.StartsWith(
                "NSG-",
                StringComparison.OrdinalIgnoreCase))
        {
            category = Category.Security;
        }
        else if (
            ruleId.StartsWith(
                "OPS-",
                StringComparison.OrdinalIgnoreCase))
        {
            category = Category.Operations;
        }
        else if (
            ruleId.StartsWith(
                "GOV-",
                StringComparison.OrdinalIgnoreCase))
        {
            category = Category.Governance;
        }
        else if (
            ruleId.StartsWith(
                "CORR-",
                StringComparison.OrdinalIgnoreCase))
        {
            category = Category.Reliability;
        }
        else if (
            ruleId.StartsWith(
                "ARCH-",
                StringComparison.OrdinalIgnoreCase))
        {
            category = Category.Architecture;
        }

        return finding with
        {
            Category = category
        };
    }

    private static Category GetEffectiveCategory(
        Finding finding)
    {
        var ruleId = finding.RuleId ?? string.Empty;

        if (ruleId.StartsWith(
                "COST-",
                StringComparison.OrdinalIgnoreCase))
        {
            return Category.Cost;
        }

        if (
            ruleId.StartsWith(
                "SEC-",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.StartsWith(
                "NSG-",
                StringComparison.OrdinalIgnoreCase))
        {
            return Category.Security;
        }

        if (ruleId.StartsWith(
                "OPS-",
                StringComparison.OrdinalIgnoreCase))
        {
            return Category.Operations;
        }

        if (ruleId.StartsWith(
                "GOV-",
                StringComparison.OrdinalIgnoreCase))
        {
            return Category.Governance;
        }

        if (ruleId.StartsWith(
                "CORR-",
                StringComparison.OrdinalIgnoreCase))
        {
            return Category.Reliability;
        }

        if (ruleId.StartsWith(
                "ARCH-",
                StringComparison.OrdinalIgnoreCase))
        {
            return Category.Architecture;
        }

        return finding.Category;
    }

    private static int GetSeverityScore(
        Severity severity)
    {
        return severity switch
        {
            Severity.Critical => 35,
            Severity.High => 28,
            Severity.Medium => 18,
            Severity.Low => 8,
            _ => 0
        };
    }

    private static int SeverityOrder(
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

    private static int GetImpactScore(
        Finding finding,
        Category effectiveCategory)
    {
        var score =
            effectiveCategory switch
            {
                Category.Security => 25,
                Category.Reliability => 24,
                Category.Architecture => 20,
                Category.Operations => 17,
                Category.Performance => 16,
                Category.Cost => 18,
                Category.Governance => 10,
                _ => 0
            };

        if (!string.IsNullOrWhiteSpace(finding.Impact))
        {
            score += 5;
        }

        return Math.Min(30, score);
    }

    private static int GetEffortScore(
        Finding finding)
    {
        var text =
            $"{finding.Title} {finding.Description} {finding.Recommendation} {finding.RuleId}"
                .ToLowerInvariant();

        if (
            text.Contains("delete") ||
            text.Contains("remove") ||
            text.Contains("disable") ||
            text.Contains("enable") ||
            text.Contains("configure") ||
            text.Contains("tag") ||
            text.Contains("rbac") ||
            text.Contains("network security group") ||
            text.Contains("nsg"))
        {
            return 6;
        }

        if (
            text.Contains("resize") ||
            text.Contains("scale") ||
            text.Contains("sku") ||
            text.Contains("tier") ||
            text.Contains("replication") ||
            text.Contains("backup"))
        {
            return 12;
        }

        if (
            text.Contains("architecture") ||
            text.Contains("redesign") ||
            text.Contains("migration") ||
            text.Contains("availability zone") ||
            text.Contains("high availability") ||
            text.Contains("domain controller"))
        {
            return 25;
        }

        return 15;
    }

    private static int GetExposureScore(
        Finding finding,
        Category effectiveCategory)
    {
        var text =
            $"{finding.Title} {finding.Description}"
                .ToLowerInvariant();

        if (
            text.Contains("public") ||
            text.Contains("internet") ||
            text.Contains("exposed") ||
            text.Contains("ssh") ||
            text.Contains("rdp") ||
            text.Contains("management"))
        {
            return 15;
        }

        if (effectiveCategory == Category.Security)
        {
            return 10;
        }

        return 5;
    }

    private static int GetScopeScore(
        Finding finding,
        Category effectiveCategory,
        IReadOnlyDictionary<string, List<Finding>>
            ruleOccurrences)
    {
        var key =
            $"{effectiveCategory}|{finding.RuleId}";

        if (!ruleOccurrences.TryGetValue(
                key,
                out var occurrences))
        {
            return 0;
        }

        return Math.Min(
            15,
            Math.Max(0, occurrences.Count - 1) * 3);
    }

    private static int GetSavingScore(
        double monthlySavingEur)
    {
        if (monthlySavingEur <= 0)
        {
            return 0;
        }

        if (monthlySavingEur >= 500)
        {
            return 15;
        }

        if (monthlySavingEur >= 200)
        {
            return 12;
        }

        if (monthlySavingEur >= 100)
        {
            return 9;
        }

        if (monthlySavingEur >= 50)
        {
            return 6;
        }

        return 3;
    }

    private static int GetRiskTypeBonus(
        Finding finding,
        Category effectiveCategory)
    {
        var ruleId =
            finding.RuleId ?? string.Empty;

        var text =
            $"{finding.Title} {finding.Description}"
                .ToLowerInvariant();

        var bonus = 0;

        if (effectiveCategory == Category.Security)
        {
            bonus += 4;
        }

        if (
            text.Contains("public") ||
            text.Contains("internet") ||
            text.Contains("exposed") ||
            text.Contains("management") ||
            text.Contains("rdp") ||
            text.Contains("ssh"))
        {
            bonus += 8;
        }

        if (
            ruleId.Contains(
                "BACKUP",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.Contains(
                "NO-HA",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.Contains(
                "NO-AVAILABILITY",
                StringComparison.OrdinalIgnoreCase))
        {
            bonus += 6;
        }

        if (
            ruleId.Contains(
                "SINGLE-REGION",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.Contains(
                "LRS",
                StringComparison.OrdinalIgnoreCase))
        {
            bonus += 3;
        }

        return Math.Min(15, bonus);
    }

    private static AssessmentPriority GetPriority(
        Severity severity,
        int priorityScore,
        Category effectiveCategory,
        int exposureScore)
    {
        return severity switch
        {
            Severity.Critical =>
                AssessmentPriority.P0,

            Severity.High when priorityScore >= 60 =>
                AssessmentPriority.P0,

            Severity.High =>
                AssessmentPriority.P1,

            Severity.Medium when priorityScore >= 55 =>
                AssessmentPriority.P1,

            Severity.Medium when priorityScore >= 35 =>
                AssessmentPriority.P2,

            Severity.Medium =>
                AssessmentPriority.P3,

            Severity.Low
                when effectiveCategory == Category.Security &&
                     exposureScore >= 15 &&
                     priorityScore >= 40 =>
                AssessmentPriority.P2,

            Severity.Low when priorityScore >= 35 =>
                AssessmentPriority.P2,

            _ =>
                AssessmentPriority.P3
        };
    }

    private static bool IsQuickWin(
        Finding finding,
        AssessmentPriority priority,
        int effortScore,
        Category effectiveCategory)
    {
        if (finding.Severity == Severity.Critical)
        {
            return false;
        }

        if (priority == AssessmentPriority.P0)
        {
            return false;
        }

        var ruleId =
            finding.RuleId ?? string.Empty;

        if (
            ruleId.Equals(
                "DISK-UNATTACHED",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.Equals(
                "PIP-UNUSED",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.Equals(
                "PIP-ORPHAN",
                StringComparison.OrdinalIgnoreCase) ||
            ruleId.Equals(
                "NSG-ORPHAN",
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (
            ruleId.Equals(
                "GOV-NO-TAGS",
                StringComparison.OrdinalIgnoreCase) &&
            effortScore <= 10)
        {
            return true;
        }

        if (
            effectiveCategory == Category.Cost &&
            effortScore <= 10)
        {
            return true;
        }

        return effortScore <= 8 &&
               priority >= AssessmentPriority.P2;
    }

    private static IntelligenceClassification GetClassification(
        Finding finding,
        AssessmentPriority priority,
        bool isQuickWin,
        Category effectiveCategory)
    {
        if (isQuickWin)
        {
            return IntelligenceClassification.QuickWin;
        }

        if (priority == AssessmentPriority.P0)
        {
            return IntelligenceClassification.CriticalRisk;
        }

        if (priority == AssessmentPriority.P1)
        {
            return IntelligenceClassification.HighPriority;
        }

        if (
            effectiveCategory == Category.Cost ||
            finding.MonthlySavingEur > 0)
        {
            return IntelligenceClassification.Optimization;
        }

        if (effectiveCategory == Category.Architecture)
        {
            return IntelligenceClassification.Optimization;
        }

        return IntelligenceClassification.HighPriority;
    }

    private static string BuildRationale(
        Finding finding,
        Category effectiveCategory,
        AssessmentPriority priority,
        int priorityScore,
        int impactScore,
        int effortScore,
        int exposureScore,
        int scopeScore,
        int savingScore,
        bool isQuickWin)
    {
        var reasons = new List<string>();

        if (finding.Severity == Severity.Critical)
        {
            reasons.Add("critical severity");
        }
        else if (finding.Severity == Severity.High)
        {
            reasons.Add("high severity");
        }

        if (impactScore >= 20)
        {
            reasons.Add("high business/technical impact");
        }

        if (exposureScore >= 15)
        {
            reasons.Add("significant exposure");
        }

        if (scopeScore >= 6)
        {
            reasons.Add("repeated pattern across resources");
        }

        if (savingScore > 0)
        {
            reasons.Add(
                "potential cost optimization");
        }

        if (isQuickWin)
        {
            reasons.Add("low implementation effort");
        }

        if (reasons.Count == 0)
        {
            reasons.Add(
                $"priority based on {effectiveCategory} assessment");
        }

        return
            $"{priority} priority (score {priorityScore}/100): " +
            $"{string.Join(", ", reasons)}. " +
            $"Estimated effort score: {effortScore}.";
    }

    private static string BuildSystemicDescription(
        Finding representative,
        int findingCount,
        int affectedResources)
    {
        return
            $"{representative.Title} affects " +
            $"{affectedResources} resource(s) across " +
            $"{findingCount} finding(s), indicating a repeated " +
            "configuration or governance pattern rather than " +
            "an isolated issue.";
    }
}