using CloudLens.Core.Azure;

namespace CloudLens.Core.Analysis;

public sealed class RiskPrioritizer
{
    public AssessmentIntelligence Analyze(
        TenantScanResult assessment)
    {
        if (assessment == null)
        {
            throw new ArgumentNullException(
                nameof(assessment));
        }

        var findings =
            assessment.AllFindings
                .Where(
                    finding =>
                        finding != null)
                .ToList();

        if (findings.Count == 0)
        {
            return new AssessmentIntelligence();
        }

        var normalizedFindings =
            findings
                .Select(
                    finding =>
                        NormalizeFindingCategory(
                            finding))
                .ToList();

        var ruleOccurrences =
            normalizedFindings
                .GroupBy(
                    finding =>
                        $"{GetEffectiveCategory(finding)}|{finding.RuleId}",
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.ToList(),
                    StringComparer.OrdinalIgnoreCase);

        var intelligenceRisks =
            normalizedFindings
                .Select(
                    finding =>
                        BuildRisk(
                            finding,
                            ruleOccurrences))
                .OrderBy(
                    risk =>
                        risk.Priority)
                .ThenByDescending(
                    risk =>
                        risk.PriorityScore)
                .ThenBy(
                    risk =>
                        SeverityOrder(
                            risk.Severity))
                .ThenBy(
                    risk =>
                        risk.Title,
                    StringComparer.OrdinalIgnoreCase)
                .ToList();

        var systemicRisks =
            BuildSystemicRisks(
                ruleOccurrences);

        var systemicFindingIds =
            systemicRisks
                .SelectMany(
                    risk =>
                        risk.FindingIds)
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

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
                                        IntelligenceClassification.SystemicRisk
                                }
                                : risk)
                    .ToList();
        }

        var quickWins =
            intelligenceRisks
                .Where(
                    risk =>
                        risk.IsQuickWin)
                .OrderBy(
                    risk =>
                        risk.Priority)
                .ThenByDescending(
                    risk =>
                        risk.PriorityScore)
                .ThenBy(
                    risk =>
                        risk.EffortScore)
                .ToList();

        var roadmap =
            BuildRoadmap(
                intelligenceRisks,
                assessment);

        return new AssessmentIntelligence
        {
            Risks =
                intelligenceRisks,

            QuickWins =
                quickWins,

            SystemicRisks =
                systemicRisks,

            Roadmap =
                roadmap
        };
    }

    private static IntelligenceRisk BuildRisk(
        Finding finding,
        IReadOnlyDictionary<
            string,
            List<Finding>> ruleOccurrences)
    {
        var effectiveCategory =
            GetEffectiveCategory(
                finding);

        var severityScore =
            GetSeverityScore(
                finding.Severity);

        var impactScore =
            GetImpactScore(
                finding,
                effectiveCategory);

        var effortScore =
            GetEffortScore(
                finding);

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
            DeterminePriority(
                finding.Severity,
                priorityScore,
                effectiveCategory,
                finding);

        var isQuickWin =
            IsQuickWin(
                finding,
                effectiveCategory,
                effortScore,
                priority);

        var classification =
            DetermineClassification(
                finding,
                effectiveCategory,
                priority,
                isQuickWin);

        var rationale =
            BuildRationale(
                finding,
                effectiveCategory,
                priority,
                priorityScore,
                impactScore,
                effortScore,
                scopeScore,
                savingScore);

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

    private static List<SystemicRisk>
        BuildSystemicRisks(
            IReadOnlyDictionary<
                string,
                List<Finding>> ruleOccurrences)
    {
        return ruleOccurrences
            .Where(
                pair =>
                    pair.Value.Count >= 3)
            .Select(
                pair =>
                {
                    var findings =
                        pair.Value;

                    var first =
                        findings.First();

                    var effectiveCategory =
                        GetEffectiveCategory(
                            first);

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
                                first.Severity) / 2 +
                            GetRiskTypeBonus(
                                first,
                                effectiveCategory) / 2,
                            0,
                            100);

                    var priority =
                        first.Severity switch
                        {
                            Severity.Critical =>
                                AssessmentPriority.P0,

                            Severity.High =>
                                AssessmentPriority.P1,

                            Severity.Medium when
                                findings.Count >= 5 =>
                                AssessmentPriority.P1,

                            _ =>
                                AssessmentPriority.P2
                        };

                    return new SystemicRisk(
                        $"SYS-{effectiveCategory}-{first.RuleId}",
                        $"Systemic issue: {first.Title}",
                        effectiveCategory,
                        first.Severity,
                        findings.Count,
                        affectedResources,
                        priority,
                        priorityScore,
                        BuildSystemicDescription(
                            first,
                            findings.Count,
                            affectedResources),
                        findings
                            .Select(
                                finding =>
                                    finding.Id)
                            .ToList());
                })
            .OrderBy(
                risk =>
                    risk.Priority)
            .ThenByDescending(
                risk =>
                    risk.PriorityScore)
            .ThenByDescending(
                risk =>
                    risk.FindingCount)
            .ToList();
    }

    private static List<RemediationRoadmapItem>
        BuildRoadmap(
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
                    action =>
                        action.FindingId,
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group =>
                        group.Key,
                    group =>
                        group
                            .OrderBy(
                                action =>
                                    action.RequiresReview)
                            .First(),
                    StringComparer.OrdinalIgnoreCase);

        return risks
            .OrderBy(
                risk =>
                    risk.Priority)
            .ThenByDescending(
                risk =>
                    risk.PriorityScore)
            .ThenByDescending(
                risk =>
                    risk.MonthlySavingEur)
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
        var effectiveCategory =
            GetEffectiveCategory(
                finding);

        if (effectiveCategory == finding.Category)
        {
            return finding;
        }

        return finding with
        {
            Category = effectiveCategory
        };
    }

    private static Category GetEffectiveCategory(
        Finding finding)
    {
        var ruleId =
            finding.RuleId
                .Trim()
                .ToUpperInvariant();

        if (ruleId.StartsWith("COST-"))
        {
            return Category.Cost;
        }

        if (ruleId.StartsWith("SEC-") ||
            ruleId.StartsWith("NSG-"))
        {
            return Category.Security;
        }

        if (ruleId.StartsWith("OPS-"))
        {
            return Category.Operations;
        }

        if (ruleId.StartsWith("GOV-"))
        {
            return Category.Governance;
        }

        if (ruleId.StartsWith("CORR-"))
        {
            return Category.Reliability;
        }

        if (ruleId.StartsWith("ARCH-"))
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

        if (!string.IsNullOrWhiteSpace(
                finding.Impact))
        {
            score += 5;
        }

        return Math.Min(
            30,
            score);
    }

    private static int GetEffortScore(
        Finding finding)
    {
        var text =
            $"{finding.Title} {finding.Recommendation}"
                .ToLowerInvariant();

        if (ContainsAny(
                text,
                "delete",
                "remove",
                "disable",
                "enable",
                "configure",
                "tag",
                "rbac",
                "network security group",
                "nsg"))
        {
            return 6;
        }

        if (ContainsAny(
                text,
                "resize",
                "scale",
                "sku",
                "tier",
                "replication",
                "backup"))
        {
            return 12;
        }

        if (ContainsAny(
                text,
                "architecture",
                "redesign",
                "migration",
                "availability zone",
                "high availability",
                "domain controller"))
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

        if (ContainsAny(
                text,
                "public",
                "internet",
                "exposed",
                "ssh",
                "rdp",
                "management"))
        {
            return 15;
        }

        if (effectiveCategory ==
            Category.Security)
        {
            return 10;
        }

        return 5;
    }

    private static int GetScopeScore(
        Finding finding,
        Category effectiveCategory,
        IReadOnlyDictionary<
            string,
            List<Finding>> ruleOccurrences)
    {
        var key =
            $"{effectiveCategory}|{finding.RuleId}";

        if (!ruleOccurrences.TryGetValue(
                key,
                out var findings))
        {
            return 0;
        }

        return Math.Min(
            15,
            Math.Max(
                0,
                (findings.Count - 1) * 3));
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
            finding.RuleId
                .Trim()
                .ToUpperInvariant();

        var text =
            $"{finding.Title} {finding.Description}"
                .ToLowerInvariant();

        var bonus = 0;

        if (effectiveCategory ==
            Category.Security)
        {
            bonus += 4;
        }

        if (ContainsAny(
                text,
                "public",
                "internet",
                "exposed",
                "management",
                "rdp",
                "ssh"))
        {
            bonus += 8;
        }

        if (ContainsAny(
                ruleId,
                "BACKUP",
                "NO-HA",
                "NO-AVAILABILITY"))
        {
            bonus += 6;
        }

        if (ContainsAny(
                ruleId,
                "SINGLE-REGION",
                "LRS"))
        {
            bonus += 3;
        }

        return Math.Min(
            15,
            bonus);
    }

    private static AssessmentPriority DeterminePriority(
        Severity severity,
        int score,
        Category effectiveCategory,
        Finding finding)
    {
        if (severity == Severity.Critical)
        {
            return AssessmentPriority.P0;
        }

        if (severity == Severity.High)
        {
            return score >= 60
                ? AssessmentPriority.P0
                : AssessmentPriority.P1;
        }

        if (severity == Severity.Medium)
        {
            if (score >= 55)
            {
                return AssessmentPriority.P1;
            }

            if (score >= 35)
            {
                return AssessmentPriority.P2;
            }

            return AssessmentPriority.P3;
        }

        if (effectiveCategory == Category.Security &&
            IsSecurityExposure(finding) &&
            score >= 40)
        {
            return AssessmentPriority.P2;
        }

        if (score >= 35)
        {
            return AssessmentPriority.P2;
        }

        return AssessmentPriority.P3;
    }

    private static IntelligenceClassification
        DetermineClassification(
            Finding finding,
            Category effectiveCategory,
            AssessmentPriority priority,
            bool isQuickWin)
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

        if (effectiveCategory ==
                Category.Cost ||
            finding.MonthlySavingEur > 0)
        {
            return IntelligenceClassification.Optimization;
        }

        if (effectiveCategory ==
            Category.Architecture)
        {
            return IntelligenceClassification.Optimization;
        }

        return IntelligenceClassification.HighPriority;
    }

    private static bool IsQuickWin(
        Finding finding,
        Category effectiveCategory,
        int effortScore,
        AssessmentPriority priority)
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
            finding.RuleId
                .Trim()
                .ToUpperInvariant();

        if (ContainsAny(
                ruleId,
                "DISK-UNATTACHED",
                "PIP-UNUSED",
                "PIP-ORPHAN",
                "NSG-ORPHAN"))
        {
            return true;
        }

        if (ruleId == "GOV-NO-TAGS" &&
            effortScore <= 10)
        {
            return true;
        }

        if (effectiveCategory == Category.Cost &&
            effortScore <= 10)
        {
            return true;
        }

        return effortScore <= 8 &&
               priority >= AssessmentPriority.P2;
    }

    private static bool IsSecurityExposure(
        Finding finding)
    {
        var text =
            $"{finding.RuleId} {finding.Title} {finding.Description}"
                .ToLowerInvariant();

        return ContainsAny(
            text,
            "public",
            "internet",
            "exposed",
            "management",
            "rdp",
            "ssh");
    }

    private static string BuildRationale(
        Finding finding,
        Category effectiveCategory,
        AssessmentPriority priority,
        int priorityScore,
        int impactScore,
        int effortScore,
        int scopeScore,
        int savingScore)
    {
        var reasons =
            new List<string>();

        if (finding.Severity ==
            Severity.Critical)
        {
            reasons.Add(
                "critical severity");
        }
        else if (finding.Severity ==
                 Severity.High)
        {
            reasons.Add(
                "high severity");
        }

        if (IsSecurityExposure(
                finding))
        {
            reasons.Add(
                "security or network exposure");
        }
        else if (effectiveCategory ==
                 Category.Reliability)
        {
            reasons.Add(
                "reliability impact");
        }
        else if (effectiveCategory ==
                 Category.Cost)
        {
            reasons.Add(
                "cost optimization impact");
        }
        else if (impactScore >= 20)
        {
            reasons.Add(
                "significant operational impact");
        }

        if (scopeScore >= 6)
        {
            reasons.Add(
                "repeated across multiple resources");
        }

        if (savingScore >= 6)
        {
            reasons.Add(
                "measurable cost-saving potential");
        }

        if (effortScore <= 10)
        {
            reasons.Add(
                "relatively low remediation effort");
        }

        if (reasons.Count == 0)
        {
            reasons.Add(
                "requires review based on the assessment findings");
        }

        return
            $"{priority} priority with score {priorityScore}/100: " +
            string.Join(
                ", ",
                reasons) +
            ".";
    }

    private static string BuildSystemicDescription(
        Finding finding,
        int findingCount,
        int affectedResources)
    {
        return
            $"The same assessment issue was detected " +
            $"{findingCount} times across " +
            $"{affectedResources} affected resources. " +
            $"This indicates a potentially systemic configuration or " +
            $"governance pattern rather than an isolated resource issue. " +
            $"Rule: {finding.RuleId}.";
    }

    private static bool ContainsAny(
        string value,
        params string[] terms)
    {
        return terms.Any(
            term =>
                value.Contains(
                    term,
                    StringComparison.OrdinalIgnoreCase));
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
}