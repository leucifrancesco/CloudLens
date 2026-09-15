using System.Text.Json;
using System.Text.Json.Serialization;

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

        var json =
            Export(assessment);

        File.WriteAllText(
            filePath,
            json);
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

        var subscriptions =
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
                .ToList();

        var inventory =
            assessment.ResourceTypes
                .Select(
                    item =>
                        new AssessmentExportResourceType(
                            item.ResourceType,
                            item.Count))
                .ToList();

        var findings =
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
                .ToList();

        var remediations =
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
                .ToList();

        var metrics =
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
                .ToList();

        return new AssessmentExportDocument
        {
            ExportVersion = "1.0",

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

            Subscriptions =
                subscriptions,

            ResourceInventory =
                inventory,

            Findings =
                findings,

            Remediations =
                remediations,

            Metrics =
                metrics,

            ScoresByCategory =
                new Dictionary<Category, int>(
                    assessment.ScoresByCategory)
        };
    }
}