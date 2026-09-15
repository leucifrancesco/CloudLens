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

        return new AssessmentExportDocument
        {
            ExportVersion = "1.1",

            ExportedAt =
                DateTimeOffset.Now,

            TenantId =
                assessment.TenantId,

            StartedAt =
                assessment.StartedAt,

            CompletedAt =
                assessment.CompletedAt,

            OverallScore =
                assessment.OverallScore,

            TotalResources =
                assessment.TotalResources,

            TotalResourceTypes =
                assessment.TotalResourceTypes,

            TotalRelationships =
                assessment.TotalRelationships,

            EnrichedResources =
                assessment.EnrichedResources,

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

            Subscriptions =
                assessment.Subscriptions
                    .Select(
                        item =>
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
                    .Select(
                        item =>
                            new AssessmentExportResourceType(
                                item.ResourceType,
                                item.Count))
                    .ToList(),

            Findings =
                assessment.AllFindings
                    .Select(
                        finding =>
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
                        item =>
                            item.Result.Remediation.Actions)
                    .Select(
                        action =>
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
                    .Select(
                        metric =>
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

    private static AssessmentExportInsights
        BuildExportInsights(
            AssessmentInsights insights)
    {
        return new AssessmentExportInsights
        {
            Severity =
                insights.Severity
                    .Select(
                        item =>
                            new AssessmentExportSeveritySummary(
                                item.Severity,
                                item.Count))
                    .ToList(),

            Categories =
                insights.Categories
                    .Select(
                        item =>
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
                    .Select(
                        item =>
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
                    .Select(
                        item =>
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
}