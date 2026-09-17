using CloudLens.Core.Analysis;
using Xunit;

namespace CloudLens.Core.Tests;

public sealed class AssessmentReportBuilderTests
{
    [Fact]
    public void HtmlReport_ShouldContainCoreSections()
    {
        var assessment =
            CreateAssessment();

        var html =
            AssessmentReportBuilder.BuildHtml(
                assessment);

        Assert.Contains(
            "CloudLens Azure Assessment",
            html);

        Assert.Contains(
            "Executive Summary",
            html);

        Assert.Contains(
            "Category Scores",
            html);

        Assert.Contains(
            "Assessment Coverage",
            html);

        Assert.Contains(
            "Subscriptions",
            html);

        Assert.Contains(
            "Resource Inventory",
            html);

        Assert.Contains(
            "Findings",
            html);

        Assert.Contains(
            "Remediation Plan",
            html);

        Assert.Contains(
            "Metrics",
            html);
    }

    [Fact]
    public void HtmlReport_ShouldContainAssessmentIntelligence()
    {
        var assessment =
            CreateAssessment();

        var html =
            AssessmentReportBuilder.BuildHtml(
                assessment);

        Assert.Contains(
            "Assessment Intelligence",
            html);

        Assert.Contains(
            "Prioritized Risks",
            html);

        Assert.Contains(
            "Quick Wins",
            html);

        Assert.Contains(
            "Systemic Risks",
            html);

        Assert.Contains(
            "Remediation Roadmap",
            html);
    }

    [Fact]
    public void HtmlReport_ShouldContainIntelligenceValues()
    {
        var assessment =
            CreateAssessment();

        var html =
            AssessmentReportBuilder.BuildHtml(
                assessment);

        Assert.Contains(
            "F-001",
            html);

        Assert.Contains(
            "Security finding",
            html);

        Assert.Contains(
            "Quick Win",
            html);

        Assert.Contains(
            "Systemic security risk",
            html);

        Assert.Contains(
            "Restrict access.",
            html);

        Assert.Contains(
            "az resource update ...",
            html);

        Assert.True(
            html.Contains("10.50 EUR") ||
            html.Contains("10,50 EUR"),
            "Expected the monthly saving value to be present in the HTML report.");
    }

    [Fact]
    public void HtmlReport_ShouldHtmlEncodeUserControlledValues()
    {
        var assessment =
            new TenantScanResult
            {
                TenantId =
                    "<script>alert('xss')</script>",
                StartedAt =
                    DateTimeOffset.UtcNow,
                CompletedAt =
                    DateTimeOffset.UtcNow,
                Intelligence =
                    new AssessmentIntelligence()
            };

        var html =
            AssessmentReportBuilder.BuildHtml(
                assessment);

        Assert.DoesNotContain(
            "<script>alert('xss')</script>",
            html);

        Assert.Contains(
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
            html);
    }

    [Fact]
    public void HtmlReport_ShouldHandleEmptyAssessment()
    {
        var assessment =
            new TenantScanResult
            {
                TenantId = "empty-test",
                StartedAt = DateTimeOffset.UtcNow,
                CompletedAt = DateTimeOffset.UtcNow,
                Intelligence = new AssessmentIntelligence()
            };

        var html =
            AssessmentReportBuilder.BuildHtml(
                assessment);

        Assert.NotEmpty(html);

        Assert.Contains(
            "No findings were identified.",
            html);

        Assert.Contains(
            "No remediation actions were generated.",
            html);

        Assert.Contains(
            "No metric profiles were collected.",
            html);
    }

    private static TenantScanResult CreateAssessment()
    {
        var risk =
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
                "Quick win");

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

            Intelligence =
                new AssessmentIntelligence
                {
                    Risks = [risk],
                    QuickWins = [risk],

                    SystemicRisks =
                    [
                        new SystemicRisk(
                            "SYS-001",
                            "Systemic security risk",
                            Category.Security,
                            Severity.Medium,
                            1,
                            1,
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
                }
        };
    }
}