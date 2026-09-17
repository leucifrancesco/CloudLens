using CloudLens.Core.Analysis;
using Xunit;

namespace CloudLens.Core.Tests;

public sealed class AssessmentIntelligenceTests
{
    [Fact]
    public void Intelligence_ShouldCalculateRiskCounters()
    {
        var intelligence = new AssessmentIntelligence
        {
            Risks =
            [
                CreateRisk(
                    "F-001",
                    AssessmentPriority.P0,
                    IntelligenceClassification.CriticalRisk,
                    95,
                    10),

                CreateRisk(
                    "F-002",
                    AssessmentPriority.P1,
                    IntelligenceClassification.HighPriority,
                    80,
                    20),

                CreateRisk(
                    "F-003",
                    AssessmentPriority.P2,
                    IntelligenceClassification.QuickWin,
                    60,
                    30),

                CreateRisk(
                    "F-004",
                    AssessmentPriority.P2,
                    IntelligenceClassification.SystemicRisk,
                    55,
                    40),

                CreateRisk(
                    "F-005",
                    AssessmentPriority.P3,
                    IntelligenceClassification.Optimization,
                    30,
                    50)
            ],

            QuickWins =
            [
                CreateRisk(
                    "F-003",
                    AssessmentPriority.P2,
                    IntelligenceClassification.QuickWin,
                    60,
                    30)
            ],

            SystemicRisks =
            [
                new SystemicRisk(
                    "SYS-001",
                    "Systemic storage risk",
                    Category.Security,
                    Severity.Medium,
                    3,
                    3,
                    AssessmentPriority.P2,
                    70,
                    "Multiple resources share the same configuration weakness.",
                    ["F-004"])
            ]
        };

        Assert.Equal(5, intelligence.TotalRisks);
        Assert.Equal(1, intelligence.P0Count);
        Assert.Equal(1, intelligence.P1Count);
        Assert.Equal(2, intelligence.P2Count);
        Assert.Equal(1, intelligence.P3Count);

        Assert.Equal(1, intelligence.QuickWinCount);
        Assert.Equal(1, intelligence.SystemicRiskCount);
    }

    [Fact]
    public void Intelligence_ShouldCalculatePotentialMonthlySavings()
    {
        var intelligence = new AssessmentIntelligence
        {
            Risks =
            [
                CreateRisk(
                    "F-001",
                    AssessmentPriority.P2,
                    IntelligenceClassification.QuickWin,
                    50,
                    12.50),

                CreateRisk(
                    "F-002",
                    AssessmentPriority.P3,
                    IntelligenceClassification.Optimization,
                    30,
                    25.75)
            ]
        };

        Assert.Equal(
            38.25,
            intelligence.PotentialMonthlySavingEur,
            precision: 2);
    }

    [Fact]
    public void Intelligence_ShouldExposeEmptyCollectionsByDefault()
    {
        var intelligence = new AssessmentIntelligence();

        Assert.Empty(intelligence.Risks);
        Assert.Empty(intelligence.QuickWins);
        Assert.Empty(intelligence.SystemicRisks);
        Assert.Empty(intelligence.Roadmap);

        Assert.Equal(0, intelligence.TotalRisks);
        Assert.Equal(0, intelligence.QuickWinCount);
        Assert.Equal(0, intelligence.SystemicRiskCount);

        Assert.Equal(0, intelligence.P0Count);
        Assert.Equal(0, intelligence.P1Count);
        Assert.Equal(0, intelligence.P2Count);
        Assert.Equal(0, intelligence.P3Count);

        Assert.Equal(
            0,
            intelligence.PotentialMonthlySavingEur);
    }

    [Fact]
    public void Intelligence_ShouldPreserveRoadmapData()
    {
        var roadmapItem =
            new RemediationRoadmapItem(
                "F-100",
                "Remove public network access",
                Category.Security,
                Severity.Medium,
                AssessmentPriority.P2,
                IntelligenceClassification.HighPriority,
                72,
                80,
                30,
                0,
                "Restrict network access to approved networks.",
                "az resource update ...",
                true);

        var intelligence = new AssessmentIntelligence
        {
            Roadmap = [roadmapItem]
        };

        var result = Assert.Single(intelligence.Roadmap);

        Assert.Equal("F-100", result.FindingId);
        Assert.Equal(AssessmentPriority.P2, result.Priority);
        Assert.Equal(
            IntelligenceClassification.HighPriority,
            result.Classification);
        Assert.Equal(72, result.PriorityScore);
        Assert.Equal(80, result.ImpactScore);
        Assert.Equal(30, result.EffortScore);
        Assert.True(result.RequiresReview);
        Assert.Equal(
            "az resource update ...",
            result.Command);
    }

    private static IntelligenceRisk CreateRisk(
        string findingId,
        AssessmentPriority priority,
        IntelligenceClassification classification,
        int priorityScore,
        double monthlySavingEur)
    {
        return new IntelligenceRisk(
            findingId,
            "RULE-TEST",
            "Test finding",
            "test-resource",
            "Microsoft.Test/resources",
            "/subscriptions/test/resourceGroups/test/providers/Microsoft.Test/resources/test",
            Category.Security,
            Severity.Medium,
            priority,
            classification,
            priorityScore,
            70,
            30,
            classification == IntelligenceClassification.QuickWin,
            classification == IntelligenceClassification.SystemicRisk,
            monthlySavingEur,
            "Test rationale");
    }
}