using System.Text.Json;
using CloudLens.Core.Analysis;
using Xunit;

namespace CloudLens.Core.Tests;

public sealed class AssessmentExportTests
{
    [Fact]
    public void JsonExport_ShouldContainAssessmentIntelligence()
    {
        var assessment =
            CreateAssessment();

        var json =
            AssessmentJsonExporter.Export(
                assessment);

        using var document =
            JsonDocument.Parse(json);

        var root =
            document.RootElement;

        Assert.True(
            root.TryGetProperty(
                "Intelligence",
                out var intelligence));

        Assert.Equal(
            2,
            intelligence
                .GetProperty("TotalRisks")
                .GetInt32());

        Assert.Equal(
            1,
            intelligence
                .GetProperty("P2Count")
                .GetInt32());

        Assert.Equal(
            1,
            intelligence
                .GetProperty("P3Count")
                .GetInt32());

        Assert.Equal(
            1,
            intelligence
                .GetProperty("QuickWinCount")
                .GetInt32());

        Assert.Equal(
            1,
            intelligence
                .GetProperty("SystemicRiskCount")
                .GetInt32());

        Assert.Equal(
            35.5,
            intelligence
                .GetProperty("PotentialMonthlySavingEur")
                .GetDouble(),
            precision: 2);
    }

    [Fact]
    public void JsonExport_ShouldContainIntelligenceCollections()
    {
        var assessment =
            CreateAssessment();

        var json =
            AssessmentJsonExporter.Export(
                assessment);

        using var document =
            JsonDocument.Parse(json);

        var intelligence =
            document.RootElement
                .GetProperty("Intelligence");

        var risks =
            intelligence.GetProperty("Risks");

        var quickWins =
            intelligence.GetProperty("QuickWins");

        var systemicRisks =
            intelligence.GetProperty("SystemicRisks");

        var roadmap =
            intelligence.GetProperty("Roadmap");

        Assert.Equal(2, risks.GetArrayLength());
        Assert.Equal(1, quickWins.GetArrayLength());
        Assert.Equal(1, systemicRisks.GetArrayLength());
        Assert.Equal(1, roadmap.GetArrayLength());
    }

    [Fact]
    public void JsonExport_ShouldPreserveRiskDetails()
    {
        var assessment =
            CreateAssessment();

        var document =
            JsonDocument.Parse(
                AssessmentJsonExporter.Export(
                    assessment));

        var firstRisk =
            document.RootElement
                .GetProperty("Intelligence")
                .GetProperty("Risks")[0];

        Assert.Equal(
            "F-001",
            firstRisk.GetProperty("FindingId").GetString());

        Assert.Equal(
            "RULE-001",
            firstRisk.GetProperty("RuleId").GetString());

        Assert.Equal(
            "Security finding",
            firstRisk.GetProperty("Title").GetString());

        Assert.Equal(
            "P2",
            firstRisk.GetProperty("Priority").GetString());

        Assert.Equal(
            "QuickWin",
            firstRisk.GetProperty("Classification").GetString());

        Assert.Equal(
            60,
            firstRisk.GetProperty("PriorityScore").GetInt32());
    }

    private static TenantScanResult CreateAssessment()
    {
        var intelligence =
            new AssessmentIntelligence
            {
                Risks =
                [
                    new IntelligenceRisk(
                        "F-001",
                        "RULE-001",
                        "Security finding",
                        "resource-01",
                        "Microsoft.Test/resources",
                        "/subscriptions/test/resource-01",
                        Category.Security,
                        Severity.Medium,
                        AssessmentPriority.P2,
                        IntelligenceClassification.QuickWin,
                        60,
                        70,
                        20,
                        true,
                        false,
                        10.50,
                        "Quick win"),

                    new IntelligenceRisk(
                        "F-002",
                        "RULE-002",
                        "Cost finding",
                        "resource-02",
                        "Microsoft.Test/resources",
                        "/subscriptions/test/resource-02",
                        Category.Cost,
                        Severity.Low,
                        AssessmentPriority.P3,
                        IntelligenceClassification.Optimization,
                        30,
                        40,
                        40,
                        false,
                        false,
                        25.00,
                        "Optimization opportunity")
                ],

                QuickWins =
                [
                    new IntelligenceRisk(
                        "F-001",
                        "RULE-001",
                        "Security finding",
                        "resource-01",
                        "Microsoft.Test/resources",
                        "/subscriptions/test/resource-01",
                        Category.Security,
                        Severity.Medium,
                        AssessmentPriority.P2,
                        IntelligenceClassification.QuickWin,
                        60,
                        70,
                        20,
                        true,
                        false,
                        10.50,
                        "Quick win")
                ],

                SystemicRisks =
                [
                    new SystemicRisk(
                        "SYS-001",
                        "Systemic security risk",
                        Category.Security,
                        Severity.Medium,
                        2,
                        2,
                        AssessmentPriority.P2,
                        65,
                        "Shared security weakness.",
                        ["F-001"])
                ],

                Roadmap =
                [
                    new RemediationRoadmapItem(
                        "F-001",
                        "Security finding",
                        Category.Security,
                        Severity.Medium,
                        AssessmentPriority.P2,
                        IntelligenceClassification.QuickWin,
                        60,
                        70,
                        20,
                        10.50,
                        "Restrict access.",
                        "az resource update ...",
                        true)
                ]
            };

        return new TenantScanResult
        {
            TenantId = "test-tenant",
            StartedAt =
                new DateTimeOffset(
                    2026,
                    9,
                    17,
                    8,
                    0,
                    0,
                    TimeSpan.Zero),
            CompletedAt =
                new DateTimeOffset(
                    2026,
                    9,
                    17,
                    8,
                    5,
                    0,
                    TimeSpan.Zero),
            Intelligence = intelligence
        };
    }
}