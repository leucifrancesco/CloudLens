using System.Text.Json;
using System.Text.Json.Serialization;
using CloudLens.Core.Analysis;

namespace CloudLens.Core;

public static class AssessmentJsonExporter
{
    private static readonly JsonSerializerOptions JsonOptions =
        new()
        {
            WriteIndented = true,

            DefaultIgnoreCondition =
                JsonIgnoreCondition.WhenWritingNull,

            Converters =
            {
                new JsonStringEnumConverter()
            }
        };

    public static string Export(
        TenantScanResult assessment)
    {
        if (assessment == null)
        {
            throw new ArgumentNullException(
                nameof(assessment));
        }

        var document =
            BuildDocument(assessment);

        return JsonSerializer.Serialize(
            document,
            JsonOptions);
    }

    public static void ExportToFile(
        TenantScanResult assessment,
        string filePath)
    {
        if (assessment == null)
        {
            throw new ArgumentNullException(
                nameof(assessment));
        }

        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException(
                "Il percorso del file non può essere vuoto.",
                nameof(filePath));
        }

        var directory =
            Path.GetDirectoryName(
                Path.GetFullPath(filePath));

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(
            filePath,
            Export(assessment));
    }

    public static AssessmentExportDocument
        BuildDocument(
            TenantScanResult assessment)
    {
        if (assessment == null)
        {
            throw new ArgumentNullException(
                nameof(assessment));
        }

        var insights =
            AssessmentInsights.Build(
                assessment);

        var quality =
            assessment.Quality;

        return new AssessmentExportDocument
        {
            ExportVersion = "1.2",
            ExportedAt = DateTimeOffset.Now,
            TenantId = assessment.TenantId,
            StartedAt = assessment.StartedAt,
            CompletedAt = assessment.CompletedAt,
            OverallScore = assessment.OverallScore,
            TotalResources = assessment.TotalResources,
            TotalResourceTypes = assessment.TotalResourceTypes,
            TotalRelationships = assessment.TotalRelationships,
            EnrichedResources = assessment.EnrichedResources,
            EnrichmentCoveragePercent =
                assessment.EnrichmentCoveragePercent,
            TotalMetricProfiles =
                assessment.TotalMetricProfiles,
            CriticalFindings =
                assessment.CriticalFindings,
            HighFindings =
                assessment.HighFindings,
            MediumFindings =
                assessment.MediumFindings,
            LowFindings =
                assessment.LowFindings,

            ScoresByCategory =
                new Dictionary<Category, int>(
                    assessment.ScoresByCategory),

            Insights =
                BuildExportInsights(
                    insights),

            Intelligence =
                BuildExportIntelligence(
                    assessment.Intelligence),

            Quality =
                BuildExportQuality(
                    quality),

            Subscriptions =
                assessment.Subscriptions
                    .Select(item =>
                        new AssessmentExportSubscription(
                            item.Subscription.Name,
                            item.Subscription.Id,
                            item.Result.Score,
                            item.Resources.Count,
                            item.Result.Stats.ResourceTypes,
                            item.Result.Findings.Count,
                            item.Result.Remediation.TotalActions))
                    .ToList(),

            ResourceInventory =
                assessment.ResourceTypes
                    .Select(item =>
                        new AssessmentExportResourceType(
                            item.ResourceType,
                            item.Count))
                    .ToList(),

            Findings =
                assessment.AllFindings
                    .Select(finding =>
                        new AssessmentExportFinding(
                            finding.Id,
                            finding.Category,
                            finding.Severity,
                            finding.RuleId,
                            finding.Title,
                            finding.Description,
                            finding.Impact,
                            finding.Recommendation,
                            finding.ResourceName,
                            finding.ResourceType,
                            finding.MonthlySavingEur,
                            finding.ResourceId,
                            finding.AzureCli))
                    .ToList(),

            Remediations =
                assessment.Subscriptions
                    .SelectMany(
                        item => item.Result.Remediation.Actions)
                    .Select(action =>
                        new AssessmentExportRemediation(
                            action.Id,
                            action.FindingId,
                            action.RuleId,
                            action.Category,
                            action.Severity,
                            action.Title,
                            action.Description,
                            action.ResourceName,
                            action.ResourceType,
                            action.ResourceId,
                            action.ActionType,
                            action.Status,
                            action.Action,
                            action.Command,
                            action.RequiresReview))
                    .ToList(),

            Metrics =
                assessment.AllMetricProfiles
                    .Select(metric =>
                        new AssessmentExportMetric(
                            metric.ResourceId,
                            metric.ResourceName,
                            metric.ResourceType,
                            metric.MetricName,
                            metric.MetricDisplayName,
                            metric.Unit,
                            metric.MetricNamespace,
                            metric.Average,
                            metric.Minimum,
                            metric.Maximum,
                            metric.SampleCount,
                            metric.LookbackDays))
                    .ToList()
        };
    }

    private static AssessmentExportQuality
        BuildExportQuality(
            AssessmentQualityReport quality)
    {
        return new AssessmentExportQuality
        {
            Status =
                quality.Status,

            TotalSubscriptions =
                quality.TotalSubscriptions,

            CompleteSubscriptions =
                quality.CompleteSubscriptions,

            PartialSubscriptions =
                quality.PartialSubscriptions,

            FailedSubscriptions =
                quality.FailedSubscriptions,

            UnsupportedSubscriptions =
                quality.UnsupportedSubscriptions,

            EnrichmentCoveragePercent =
                quality.EnrichmentCoveragePercent,

            MetricCoveragePercent =
                quality.MetricCoveragePercent,

            Limitations =
                quality.Limitations
                    .ToList(),

            Subscriptions =
                quality.Subscriptions
                    .Select(item =>
                    {
                        var totalResources =
                            item.Resources.Count;

                        var enrichedResources =
                            item.Resources.Count(
                                resource =>
                                    resource.Enrichment?.Success ==
                                    true);

                        var metricResourceIds =
                            item.Result.MetricProfiles
                                .Select(
                                    metric =>
                                        metric.ResourceId)
                                .Where(
                                    id =>
                                        !string.IsNullOrWhiteSpace(id))
                                .Distinct(
                                    StringComparer.OrdinalIgnoreCase)
                                .Count();

                        var enrichmentCoverage =
                            totalResources == 0
                                ? 0
                                : enrichedResources * 100.0 /
                                  totalResources;

                        var metricCoverage =
                            totalResources == 0
                                ? 0
                                : metricResourceIds * 100.0 /
                                  totalResources;

                        return
                            new AssessmentExportSubscriptionQuality(
                                item.Subscription.Name,
                                item.Subscription.Id,
                                item.Status,
                                item.ErrorMessage,
                                totalResources,
                                enrichedResources,
                                enrichmentCoverage,
                                item.Result.MetricProfiles.Count,
                                metricCoverage,
                                item.Result.Coverage
                                    .SupportedResourceTypes,
                                item.Result.Coverage
                                    .GenericResourceTypes,
                                item.Result.Coverage
                                    .UnsupportedResourceTypes);
                    })
                    .ToList()
        };
    }

    private static AssessmentExportInsights
        BuildExportInsights(
            AssessmentInsights insights)
    {
        return new AssessmentExportInsights
        {
            Severity =
                insights.Severity
                    .Select(item =>
                        new AssessmentExportSeveritySummary(
                            item.Severity,
                            item.Count))
                    .ToList(),

            Categories =
                insights.Categories
                    .Select(item =>
                        new AssessmentExportCategorySummary(
                            item.Category,
                            item.Score,
                            item.FindingCount,
                            item.CriticalCount,
                            item.HighCount,
                            item.MediumCount,
                            item.LowCount))
                    .ToList(),

            TopRisks =
                insights.TopRisks
                    .Select(item =>
                        new AssessmentExportRiskItem(
                            item.FindingId,
                            item.RuleId,
                            item.Title,
                            item.Category,
                            item.Severity,
                            item.ResourceName,
                            item.ResourceType,
                            item.ResourceId,
                            item.Impact,
                            item.Recommendation,
                            item.MonthlySavingEur))
                    .ToList(),

            Remediation =
                insights.Remediation
                    .Select(item =>
                        new AssessmentExportRemediationSummary(
                            item.Status,
                            item.Count,
                            item.CriticalCount,
                            item.HighCount))
                    .ToList(),

            Coverage =
                new AssessmentExportCoverageSummary
                {
                    TotalResources =
                        insights.Coverage.TotalResources,

                    EnrichedResources =
                        insights.Coverage.EnrichedResources,

                    EnrichmentCoveragePercent =
                        insights.Coverage.EnrichmentCoveragePercent,

                    TotalResourceTypes =
                        insights.Coverage.TotalResourceTypes,

                    SupportedResourceTypes =
                        insights.Coverage.SupportedResourceTypes,

                    GenericResourceTypes =
                        insights.Coverage.GenericResourceTypes,

                    UnsupportedResourceTypes =
                        insights.Coverage.UnsupportedResourceTypes,

                    ResourceTypeCoveragePercent =
                        insights.Coverage.ResourceTypeCoveragePercent,

                    SpecializedAnalyzerCoveragePercent =
                        insights.Coverage.SpecializedAnalyzerCoveragePercent,

                    MetricCapableResources =
                        insights.Coverage.MetricCapableResources,

                    MetricProfiles =
                        insights.Coverage.MetricProfiles
                }
        };
    }

    private static AssessmentExportIntelligence
        BuildExportIntelligence(
            AssessmentIntelligence intelligence)
    {
        return new AssessmentExportIntelligence
        {
            TotalRisks =
                intelligence.TotalRisks,

            P0Count =
                intelligence.P0Count,

            P1Count =
                intelligence.P1Count,

            P2Count =
                intelligence.P2Count,

            P3Count =
                intelligence.P3Count,

            QuickWinCount =
                intelligence.QuickWinCount,

            SystemicRiskCount =
                intelligence.SystemicRiskCount,

            PotentialMonthlySavingEur =
                intelligence.PotentialMonthlySavingEur,

            Risks =
                intelligence.Risks
                    .Select(item =>
                        new AssessmentExportIntelligenceRisk(
                            item.FindingId,
                            item.RuleId,
                            item.Title,
                            item.ResourceName,
                            item.ResourceType,
                            item.ResourceId,
                            item.Category,
                            item.Severity,
                            item.Priority,
                            item.Classification,
                            item.PriorityScore,
                            item.ImpactScore,
                            item.EffortScore,
                            item.IsQuickWin,
                            item.IsSystemic,
                            item.MonthlySavingEur,
                            item.Rationale))
                    .ToList(),

            QuickWins =
                intelligence.QuickWins
                    .Select(item =>
                        new AssessmentExportQuickWin(
                            item.FindingId,
                            item.Title,
                            item.ResourceName,
                            item.ResourceType,
                            item.Category,
                            item.Severity,
                            item.Priority,
                            item.PriorityScore,
                            item.ImpactScore,
                            item.EffortScore,
                            item.MonthlySavingEur,
                            item.Rationale))
                    .ToList(),

            SystemicRisks =
                intelligence.SystemicRisks
                    .Select(item =>
                        new AssessmentExportSystemicRisk(
                            item.Id,
                            item.Title,
                            item.Category,
                            item.Severity,
                            item.FindingCount,
                            item.AffectedResources,
                            item.Priority,
                            item.PriorityScore,
                            item.Description,
                            item.FindingIds))
                    .ToList(),

            Roadmap =
                intelligence.Roadmap
                    .Select(item =>
                        new AssessmentExportRoadmapItem(
                            item.FindingId,
                            item.Title,
                            item.Category,
                            item.Severity,
                            item.Priority,
                            item.Classification,
                            item.PriorityScore,
                            item.ImpactScore,
                            item.EffortScore,
                            item.MonthlySavingEur,
                            item.Action,
                            item.Command,
                            item.RequiresReview))
                    .ToList()
        };
    }
}