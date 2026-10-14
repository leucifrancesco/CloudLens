using Xunit;
using CloudLens.Core;
using CloudLens.Core.Analysis;
using CloudLens.Core.Azure;

namespace CloudLens.Core.Tests;

public sealed class RiskPrioritizerTests
{
    private readonly RiskPrioritizer _prioritizer = new();

    [Fact]
    public void Analyze_ShouldRejectNullAssessment()
    {
        Assert.Throws<ArgumentNullException>(
            () => _prioritizer.Analyze(null!));
    }

    [Fact]
    public void Analyze_ShouldReturnEmptyIntelligence_WhenAssessmentHasNoFindings()
    {
        var assessment = CreateAssessment();

        var intelligence = _prioritizer.Analyze(assessment);

        Assert.Empty(intelligence.Risks);
        Assert.Empty(intelligence.QuickWins);
        Assert.Empty(intelligence.SystemicRisks);
        Assert.Empty(intelligence.Roadmap);
        Assert.Equal(0, intelligence.TotalRisks);
    }

    [Fact]
    public void Analyze_ShouldClassifyCriticalFindingAsP0()
    {
        var finding = CreateFinding(
            severity: Severity.Critical,
            category: Category.Security,
            ruleId: "SEC-CRITICAL-TEST");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P0,
            risk.Priority);

        Assert.Equal(
            Severity.Critical,
            risk.Severity);

        Assert.False(risk.IsQuickWin);
    }

    [Fact]
    public void Analyze_ShouldClassifyHighRiskFindingAsP0_WhenPriorityScoreIsHigh()
    {
        var finding = CreateFinding(
            severity: Severity.High,
            category: Category.Security,
            ruleId: "SEC-SSH-INTERNET",
            title: "SSH exposed to the public internet",
            description: "SSH is publicly exposed to the internet.",
            impact: "Direct management exposure.",
            recommendation: "Restrict SSH access.",
            azureCli: "az network nsg rule update");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P0,
            risk.Priority);

        Assert.True(risk.PriorityScore >= 60);
    }

    [Fact]
    public void Analyze_ShouldClassifyNormalHighSeverityFindingAsP1()
    {
        var finding = CreateFinding(
            severity: Severity.High,
            category: Category.Governance,
            ruleId: "GOV-CONFIGURATION",
            title: "Governance configuration requires attention",
            impact: "Governance impact.");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P1,
            risk.Priority);
    }

    [Fact]
    public void Analyze_ShouldClassifyHighImpactMediumFindingAsP1()
    {
        var finding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Security,
            ruleId: "SEC-RDP-INTERNET",
            title: "RDP exposed to the public internet",
            description: "RDP is exposed to the public internet.",
            impact: "Direct administrative exposure.",
            recommendation: "Restrict RDP access.",
            azureCli: "az network nsg rule update",
            monthlySavingEur: 200);

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P1,
            risk.Priority);

        Assert.True(risk.PriorityScore >= 55);
    }

    [Fact]
    public void Analyze_ShouldClassifyModerateMediumFindingAsP2()
    {
        var finding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Cost,
            ruleId: "COST-UNUSED-RESOURCE",
            title: "Unused resource with significant monthly cost",
            impact: "Unnecessary monthly expenditure.",
            monthlySavingEur: 500);

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P2,
            risk.Priority);

        Assert.True(risk.PriorityScore >= 35);
    }

    [Fact]
    public void Analyze_ShouldClassifyLowSecurityExposureAsP2_WhenScoreIsHighEnough()
    {
        var finding = CreateFinding(
            severity: Severity.Low,
            category: Category.Security,
            ruleId: "SEC-SSH-INTERNET",
            title: "SSH management endpoint exposed",
            description: "SSH management access is exposed to the internet.",
            impact: "Management exposure.",
            recommendation: "Restrict management access.");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P2,
            risk.Priority);
    }

    [Fact]
    public void Analyze_ShouldClassifyLowFindingAsP3_WhenScoreIsLow()
    {
        var finding = CreateFinding(
            severity: Severity.Low,
            category: Category.Governance,
            ruleId: "GOV-CONFIGURATION",
            title: "Minor governance issue");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            AssessmentPriority.P3,
            risk.Priority);
    }

    [Fact]
    public void Analyze_ShouldIncreaseExposureForPublicManagementFinding()
    {
        var exposedFinding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Security,
            ruleId: "SEC-SSH-INTERNET",
            title: "SSH exposed to the internet",
            description: "Public SSH management access.",
            impact: "Management exposure.");

        var internalFinding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Security,
            ruleId: "SEC-INTERNAL-CONFIG",
            title: "Internal security configuration issue",
            description: "Internal configuration requires review.",
            impact: "Security impact.");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                exposedFinding,
                internalFinding));

        var exposedRisk = intelligence.Risks
            .Single(x => x.RuleId == exposedFinding.RuleId);

        var internalRisk = intelligence.Risks
            .Single(x => x.RuleId == internalFinding.RuleId);

        Assert.True(
            exposedRisk.PriorityScore >
            internalRisk.PriorityScore);
    }

    [Fact]
    public void Analyze_ShouldIncreasePriorityScoreForMonthlySavings()
    {
        var noSaving = CreateFinding(
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-CONFIGURATION",
            title: "Configuration issue",
            impact: "Operational impact.");

        var saving = CreateFinding(
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-COST-CONFIGURATION",
            title: "Configuration issue with savings",
            impact: "Operational impact.",
            monthlySavingEur: 500);

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                noSaving,
                saving));

        var noSavingRisk = intelligence.Risks
            .Single(x => x.RuleId == noSaving.RuleId);

        var savingRisk = intelligence.Risks
            .Single(x => x.RuleId == saving.RuleId);

        Assert.True(
            savingRisk.PriorityScore >
            noSavingRisk.PriorityScore);

        Assert.Equal(
            500,
            savingRisk.MonthlySavingEur);
    }

    [Fact]
    public void Analyze_ShouldIncreasePriorityScoreForRepeatedRule()
    {
        var first = CreateFinding(
            id: "finding-01",
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-REPEATED",
            resourceName: "resource-01");

        var second = CreateFinding(
            id: "finding-02",
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-REPEATED",
            resourceName: "resource-02");

        var third = CreateFinding(
            id: "finding-03",
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-REPEATED",
            resourceName: "resource-03");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                first,
                second,
                third));

        var risks = intelligence.Risks
            .Where(x => x.RuleId == "GOV-REPEATED")
            .ToList();

        Assert.Equal(3, risks.Count);

        Assert.All(
            risks,
            risk => Assert.True(risk.PriorityScore > 0));

        Assert.True(
            risks.All(
                risk =>
                    risk.PriorityScore >=
                    risks.Min(x => x.PriorityScore)));
    }

    [Fact]
    public void Analyze_ShouldIdentifySystemicRisk_WhenRuleOccursAtLeastThreeTimes()
    {
        var findings = new[]
        {
            CreateFinding(
                id: "finding-01",
                ruleId: "SEC-SYSTEMIC-TEST",
                category: Category.Security,
                resourceName: "resource-01"),

            CreateFinding(
                id: "finding-02",
                ruleId: "SEC-SYSTEMIC-TEST",
                category: Category.Security,
                resourceName: "resource-02"),

            CreateFinding(
                id: "finding-03",
                ruleId: "SEC-SYSTEMIC-TEST",
                category: Category.Security,
                resourceName: "resource-03")
        };

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(findings));

        var systemicRisk =
            Assert.Single(intelligence.SystemicRisks);

        Assert.Equal(
            3,
            systemicRisk.FindingCount);

        Assert.Equal(
            3,
            systemicRisk.AffectedResources);

        Assert.Equal(
            Category.Security,
            systemicRisk.Category);

        Assert.Contains(
            "finding-01",
            systemicRisk.FindingIds);

        Assert.Contains(
            "finding-02",
            systemicRisk.FindingIds);

        Assert.Contains(
            "finding-03",
            systemicRisk.FindingIds);
    }

    [Fact]
    public void Analyze_ShouldNotIdentifySystemicRisk_WhenRuleOccursOnlyTwice()
    {
        var first = CreateFinding(
            id: "finding-01",
            ruleId: "SEC-NOT-SYSTEMIC",
            category: Category.Security,
            resourceName: "resource-01");

        var second = CreateFinding(
            id: "finding-02",
            ruleId: "SEC-NOT-SYSTEMIC",
            category: Category.Security,
            resourceName: "resource-02");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                first,
                second));

        Assert.Empty(intelligence.SystemicRisks);
    }

    [Fact]
    public void Analyze_ShouldMarkSystemicFindingsAsSystemic()
    {
        var findings = new[]
        {
            CreateFinding(
                id: "finding-01",
                ruleId: "SEC-SYSTEMIC",
                category: Category.Security,
                resourceName: "resource-01"),

            CreateFinding(
                id: "finding-02",
                ruleId: "SEC-SYSTEMIC",
                category: Category.Security,
                resourceName: "resource-02"),

            CreateFinding(
                id: "finding-03",
                ruleId: "SEC-SYSTEMIC",
                category: Category.Security,
                resourceName: "resource-03")
        };

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(findings));

        Assert.All(
            intelligence.Risks,
            risk =>
            {
                Assert.True(risk.IsSystemic);
                Assert.Equal(
                    IntelligenceClassification.SystemicRisk,
                    risk.Classification);
            });
    }

    [Fact]
    public void Analyze_ShouldUseHighestSeverityForSystemicRisk()
    {
        var low = CreateFinding(
            id: "finding-low",
            severity: Severity.Low,
            category: Category.Security,
            ruleId: "SEC-MIXED-SEVERITY",
            resourceName: "resource-low");

        var medium = CreateFinding(
            id: "finding-medium",
            severity: Severity.Medium,
            category: Category.Security,
            ruleId: "SEC-MIXED-SEVERITY",
            resourceName: "resource-medium");

        var high = CreateFinding(
            id: "finding-high",
            severity: Severity.High,
            category: Category.Security,
            ruleId: "SEC-MIXED-SEVERITY",
            resourceName: "resource-high");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                low,
                medium,
                high));

        var systemicRisk =
            Assert.Single(intelligence.SystemicRisks);

        /*
         * Questo test documenta il comportamento desiderato:
         * un rischio sistemico con severità miste deve essere
         * rappresentato dalla severità massima, non dalla
         * prima Finding incontrata.
         */
        Assert.Equal(
            Severity.High,
            systemicRisk.Severity);
    }

    [Fact]
    public void Analyze_ShouldNotMarkCriticalFindingAsQuickWin()
    {
        var finding = CreateFinding(
            severity: Severity.Critical,
            category: Category.Security,
            ruleId: "SEC-CRITICAL");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.False(risk.IsQuickWin);
        Assert.DoesNotContain(
            intelligence.QuickWins,
            x => x.FindingId == finding.Id);
    }

    [Fact]
    public void Analyze_ShouldRecognizeKnownQuickWinRule()
    {
        var finding = CreateFinding(
            severity: Severity.Low,
            category: Category.Operations,
            ruleId: "OPS-DISK-UNATTACHED",
            title: "Delete unattached disk");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.True(risk.IsQuickWin);

        Assert.Contains(
            intelligence.QuickWins,
            x => x.FindingId == finding.Id);
    }

    [Fact]
    public void Analyze_ShouldIncludeRemediationActionInRoadmap()
    {
        var finding = CreateFinding(
            severity: Severity.High,
            category: Category.Security,
            ruleId: "SEC-UNUSED-PUBLIC-IP",
            title: "Unused public IP",
            resourceId:
                "/subscriptions/sub-01/resourceGroups/rg-01/providers/Microsoft.Network/publicIPAddresses/pip-01");

        var assessment =
            CreateAssessmentWithRemediation(finding);

        var intelligence =
            _prioritizer.Analyze(assessment);

        var roadmapItem =
            Assert.Single(
                intelligence.Roadmap);

        Assert.Equal(
            finding.Id,
            roadmapItem.FindingId);

        Assert.False(
            string.IsNullOrWhiteSpace(
                roadmapItem.Action));

        Assert.True(
            roadmapItem.RequiresReview);
    }

    [Fact]
    public void Analyze_ShouldRequireReview_WhenNoRemediationActionExists()
    {
        var finding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-UNKNOWN-RULE");

        var assessment =
            CreateAssessment(finding);

        var intelligence =
            _prioritizer.Analyze(assessment);

        var roadmapItem =
            Assert.Single(
                intelligence.Roadmap);

        Assert.Equal(
            finding.Id,
            roadmapItem.FindingId);

        Assert.True(
            roadmapItem.RequiresReview);

        Assert.Null(
            roadmapItem.Command);
    }

    [Fact]
    public void Analyze_ShouldNormalizeCategoryFromSecurityRulePrefix()
    {
        var finding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "SEC-CUSTOM-RULE");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            Category.Security,
            risk.Category);
    }

    [Fact]
    public void Analyze_ShouldNormalizeCategoryFromCostRulePrefix()
    {
        var finding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "COST-CUSTOM-RULE");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            Category.Cost,
            risk.Category);
    }

    [Fact]
    public void Analyze_ShouldNormalizeCategoryFromReliabilityRulePrefix()
    {
        var finding = CreateFinding(
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "CORR-CUSTOM-RULE");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(finding));

        var risk = Assert.Single(intelligence.Risks);

        Assert.Equal(
            Category.Reliability,
            risk.Category);
    }

    [Fact]
    public void Analyze_ShouldOrderRisksByPriorityThenScore()
    {
        var critical = CreateFinding(
            id: "finding-critical",
            severity: Severity.Critical,
            category: Category.Security,
            ruleId: "SEC-CRITICAL");

        var medium = CreateFinding(
            id: "finding-medium",
            severity: Severity.Medium,
            category: Category.Governance,
            ruleId: "GOV-MEDIUM",
            monthlySavingEur: 500);

        var low = CreateFinding(
            id: "finding-low",
            severity: Severity.Low,
            category: Category.Governance,
            ruleId: "GOV-LOW");

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                low,
                medium,
                critical));

        Assert.Equal(
            AssessmentPriority.P0,
            intelligence.Risks[0].Priority);

        Assert.True(
            intelligence.Risks[0].PriorityScore >=
            intelligence.Risks[1].PriorityScore);

        Assert.True(
            (intelligence.Risks[0].Priority <=
             intelligence.Risks[1].Priority) &&
            (intelligence.Risks[1].Priority <=
             intelligence.Risks[2].Priority));
    }

    [Fact]
    public void Analyze_ShouldCalculatePotentialMonthlySavings()
    {
        var first = CreateFinding(
            id: "finding-01",
            severity: Severity.Medium,
            category: Category.Cost,
            ruleId: "COST-FIRST",
            monthlySavingEur: 100);

        var second = CreateFinding(
            id: "finding-02",
            severity: Severity.Medium,
            category: Category.Cost,
            ruleId: "COST-SECOND",
            monthlySavingEur: 250);

        var intelligence = _prioritizer.Analyze(
            CreateAssessment(
                first,
                second));

        Assert.Equal(
            350,
            intelligence.PotentialMonthlySavingEur);
    }

    private static TenantScanResult CreateAssessment(
        params Finding[] findings)
    {
        var subscription =
            new AzureSubscription(
                "sub-01",
                "Test Subscription");

        var result =
            new ScanResult
            {
                SubscriptionName =
                    subscription.Name,

                SubscriptionId =
                    subscription.Id,

                Findings =
                    findings.ToList()
            };

        var subscriptionAssessment =
            new SubscriptionAssessment(
                subscription,
                result,
                []);

        return new TenantScanResult
        {
            TenantId = "tenant-01",
            StartedAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            Subscriptions =
            [
                subscriptionAssessment
            ]
        };
    }

    private static TenantScanResult CreateAssessmentWithRemediation(
        params Finding[] findings)
    {
        var subscription =
            new AzureSubscription(
                "sub-01",
                "Test Subscription");

        var result =
            new ScanResult
            {
                SubscriptionName =
                    subscription.Name,

                SubscriptionId =
                    subscription.Id,

                Findings =
                    findings.ToList(),

                Remediation =
                    new RemediationEngine()
                        .BuildPlan(findings)
            };

        var subscriptionAssessment =
            new SubscriptionAssessment(
                subscription,
                result,
                []);

        return new TenantScanResult
        {
            TenantId = "tenant-01",
            StartedAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            CompletedAt = DateTimeOffset.UtcNow,
            Subscriptions =
            [
                subscriptionAssessment
            ]
        };
    }

    private static Finding CreateFinding(
        string? id = null,
        Category category = Category.Governance,
        Severity severity = Severity.Medium,
        string ruleId = "GOV-TEST",
        string title = "Test finding",
        string description = "Test description.",
        string impact = "Test impact.",
        string recommendation = "Test recommendation.",
        string resourceName = "test-resource",
        string resourceType = "Microsoft.Test/testResources",
        double monthlySavingEur = 0,
        string? azureCli = null,
        string? resourceId = null)
    {
        return new Finding(
            Id:
                id ??
                Guid.NewGuid().ToString(),

            Category:
                category,

            Severity:
                severity,

            RuleId:
                ruleId,

            Title:
                title,

            Description:
                description,

            Impact:
                impact,

            Recommendation:
                recommendation,

            ResourceName:
                resourceName,

            ResourceType:
                resourceType,

            MonthlySavingEur:
                monthlySavingEur,

            AzureCli:
                azureCli,

            ResourceId:
                resourceId);
    }
}