using System.Net;
using System.Text;
using CloudLens.Core.Analysis;

namespace CloudLens.Core;

public static class AssessmentReportBuilder
{
public static string BuildHtml(
TenantScanResult assessment)
{
if (assessment == null)
{
throw new ArgumentNullException(
nameof(assessment));
}

    var html =
        new StringBuilder();

    html.AppendLine(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>CloudLens Azure Assessment</title>
          <style>
            body {
              font-family: Segoe UI, Arial, sans-serif;
              margin: 0;
              background: #f5f7fa;
              color: #172033;
            }
            .container {
              max-width: 1400px;
              margin: 0 auto;
              padding: 40px;
            }
            .header {
              background: #0d1524;
              color: white;
              padding: 30px;
              border-radius: 12px;
              margin-bottom: 24px;
            }
            h1 { margin: 0 0 8px 0; }
            h2 {
              margin-top: 36px;
              border-bottom: 1px solid #dfe5ec;
              padding-bottom: 8px;
            }
            .muted { color: #667085; }
            .grid {
              display: grid;
              grid-template-columns:
                repeat(auto-fit,minmax(180px,1fr));
              gap: 12px;
            }
            .card {
              background: white;
              border: 1px solid #e1e6ec;
              border-radius: 10px;
              padding: 18px;
            }
            .value {
              font-size: 28px;
              font-weight: 700;
              margin-top: 5px;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              background: white;
              margin-top: 12px;
            }
            th, td {
              padding: 10px;
              border-bottom: 1px solid #e5e7eb;
              text-align: left;
              vertical-align: top;
            }
            th {
              background: #eef2f6;
            }
            .critical { font-weight: 700; }
            .high { font-weight: 700; }
            .medium { font-weight: 600; }
            .low { font-weight: 500; }
            .ready {
              font-weight: 700;
            }
            .reviewrequired {
              font-weight: 700;
            }
            .notautomatable {
              font-weight: 700;
            }
            .section {
              background: white;
              border: 1px solid #e1e6ec;
              border-radius: 10px;
              padding: 20px;
              margin-top: 16px;
            }
            .command {
              display: block;
              white-space: pre-wrap;
              word-break: break-word;
              background: #f1f3f5;
              border: 1px solid #d9dee5;
              border-radius: 6px;
              padding: 8px;
              margin-top: 6px;
            }
            code {
              font-family: Consolas, monospace;
              font-size: 12px;
            }
          </style>
        </head>
        <body>
        <div class="container">
        """);

    html.AppendLine(
        "<div class=\"header\">");

    html.AppendLine(
        "<h1>CloudLens Azure Assessment</h1>");

    html.AppendLine(
        $"<div>Tenant: " +
        $"{Encode(assessment.TenantId)}</div>");

    html.AppendLine(
        $"<div>Generated: " +
        $"{assessment.CompletedAt.LocalDateTime:g}</div>");

    html.AppendLine(
        "</div>");

    AppendExecutiveSummary(
        html,
        assessment);

    AppendCoverage(
        html,
        assessment);

    AppendSubscriptions(
        html,
        assessment);

    AppendResourceInventory(
        html,
        assessment);

    AppendFindings(
        html,
        assessment);

    AppendRemediation(
        html,
        assessment);

    AppendMetrics(
        html,
        assessment);

    html.AppendLine(
        """
        </div>
        </body>
        </html>
        """);

    return html.ToString();
}

private static void AppendExecutiveSummary(
    StringBuilder html,
    TenantScanResult assessment)
{
    html.AppendLine(
        "<h2>Executive Summary</h2>");

    html.AppendLine(
        "<div class=\"grid\">");

    AppendCard(
        html,
        "Overall Score",
        $"{assessment.OverallScore}/100");

    AppendCard(
        html,
        "Subscriptions",
        assessment.Subscriptions.Count.ToString());

    AppendCard(
        html,
        "Resources",
        assessment.TotalResources.ToString());

    AppendCard(
        html,
        "Resource Types",
        assessment.TotalResourceTypes.ToString());

    AppendCard(
        html,
        "Critical",
        assessment.CriticalFindings.ToString());

    AppendCard(
        html,
        "High",
        assessment.HighFindings.ToString());

    AppendCard(
        html,
        "Medium",
        assessment.MediumFindings.ToString());

    AppendCard(
        html,
        "Low",
        assessment.LowFindings.ToString());

    html.AppendLine(
        "</div>");

    html.AppendLine(
        "<div class=\"section\">");

    html.AppendLine(
        "<strong>Assessment interpretation</strong>");

    html.AppendLine(
        $"<p>{GetScoreDescription(assessment.OverallScore)}</p>");

    html.AppendLine(
        "</div>");
}

private static void AppendCoverage(
    StringBuilder html,
    TenantScanResult assessment)
{
    html.AppendLine(
        "<h2>Assessment Coverage</h2>");

    html.AppendLine(
        "<div class=\"grid\">");

    AppendCard(
        html,
        "ARM Enrichment",
        $"{assessment.EnrichmentCoveragePercent:F1}%");

    AppendCard(
        html,
        "Relationships",
        assessment.TotalRelationships.ToString());

    AppendCard(
        html,
        "Metric Profiles",
        assessment.TotalMetricProfiles.ToString());

    AppendCard(
        html,
        "Scan Duration",
        $"{(assessment.CompletedAt - assessment.StartedAt).TotalMinutes:F1} min");

    html.AppendLine(
        "</div>");
}

private static void AppendSubscriptions(
    StringBuilder html,
    TenantScanResult assessment)
{
    html.AppendLine(
        "<h2>Subscriptions</h2>");

    html.AppendLine(
        "<table>");

    html.AppendLine(
        "<tr>" +
        "<th>Subscription</th>" +
        "<th>Score</th>" +
        "<th>Resources</th>" +
        "<th>Resource Types</th>" +
        "<th>Findings</th>" +
        "<th>Remediations</th>" +
        "</tr>");

    foreach (var item in
             assessment.Subscriptions)
    {
        html.AppendLine(
            "<tr>");

        html.AppendLine(
            $"<td>{Encode(item.Subscription.Name)}<br>" +
            $"<code>{Encode(item.Subscription.Id)}</code></td>");

        html.AppendLine(
            $"<td>{item.Result.Score}/100</td>");

        html.AppendLine(
            $"<td>{item.Resources.Count}</td>");

        html.AppendLine(
            $"<td>{item.Result.Stats.ResourceTypes}</td>");

        html.AppendLine(
            $"<td>{item.Result.Findings.Count}</td>");

        html.AppendLine(
            $"<td>{item.Result.Remediation.TotalActions}</td>");

        html.AppendLine(
            "</tr>");
    }

    html.AppendLine(
        "</table>");
}

private static void AppendResourceInventory(
    StringBuilder html,
    TenantScanResult assessment)
{
    html.AppendLine(
        "<h2>Resource Inventory</h2>");

    html.AppendLine(
        "<table>");

    html.AppendLine(
        "<tr>" +
        "<th>Resource Type</th>" +
        "<th>Count</th>" +
        "</tr>");

    foreach (var summary in
             assessment.ResourceTypes)
    {
        html.AppendLine(
            "<tr>");

        html.AppendLine(
            $"<td><code>{Encode(summary.ResourceType)}</code></td>");

        html.AppendLine(
            $"<td>{summary.Count}</td>");

        html.AppendLine(
            "</tr>");
    }

    html.AppendLine(
        "</table>");
}

private static void AppendFindings(
    StringBuilder html,
    TenantScanResult assessment)
{
    html.AppendLine(
        "<h2>Findings</h2>");

    if (assessment.AllFindings.Count == 0)
    {
        html.AppendLine(
            "<div class=\"section\">" +
            "No findings were identified." +
            "</div>");

        return;
    }

    html.AppendLine(
        "<table>");

    html.AppendLine(
        "<tr>" +
        "<th>Severity</th>" +
        "<th>Category</th>" +
        "<th>Rule</th>" +
        "<th>Resource</th>" +
        "<th>Description</th>" +
        "<th>Recommendation</th>" +
        "</tr>");

    foreach (var finding in
             assessment.AllFindings
                .OrderBy(
                    x =>
                        SeverityOrder(
                            x.Severity))
                .ThenBy(
                    x => x.Category)
                .ThenBy(
                    x => x.ResourceName,
                    StringComparer.OrdinalIgnoreCase))
    {
        html.AppendLine(
            "<tr>");

        html.AppendLine(
            $"<td class=\"{finding.Severity.ToString().ToLowerInvariant()}\">" +
            $"{finding.Severity}</td>");

        html.AppendLine(
            $"<td>{finding.Category}</td>");

        html.AppendLine(
            $"<td><code>{Encode(finding.RuleId)}</code></td>");

        html.AppendLine(
            $"<td>{Encode(finding.ResourceName)}<br>" +
            $"<code>{Encode(finding.ResourceType)}</code></td>");

        html.AppendLine(
            $"<td>{Encode(finding.Description)}</td>");

        html.AppendLine(
            $"<td>{Encode(finding.Recommendation)}</td>");

        html.AppendLine(
            "</tr>");
    }

    html.AppendLine(
        "</table>");
}

private static void AppendRemediation(
    StringBuilder html,
    TenantScanResult assessment)
{
    var actions =
        assessment.Subscriptions
            .SelectMany(
                subscription =>
                    subscription
                        .Result
                        .Remediation
                        .Actions)
            .OrderByDescending(
                action =>
                    SeverityOrder(
                        action.Severity))
            .ThenBy(
                action => action.Category)
            .ThenBy(
                action => action.ResourceName,
                StringComparer.OrdinalIgnoreCase)
            .ToList();

    var total =
        actions.Count;

    var ready =
        actions.Count(
            action =>
                action.Status ==
                RemediationStatus.Ready);

    var reviewRequired =
        actions.Count(
            action =>
                action.Status ==
                RemediationStatus.ReviewRequired);

    var notAutomatable =
        actions.Count(
            action =>
                action.Status ==
                RemediationStatus.NotAutomatable);

    html.AppendLine(
        "<h2>Remediation Plan</h2>");

    html.AppendLine(
        "<div class=\"grid\">");

    AppendCard(
        html,
        "Total Actions",
        total.ToString());

    AppendCard(
        html,
        "Ready",
        ready.ToString());

    AppendCard(
        html,
        "Review Required",
        reviewRequired.ToString());

    AppendCard(
        html,
        "Not Automatable",
        notAutomatable.ToString());

    html.AppendLine(
        "</div>");

    if (total == 0)
    {
        html.AppendLine(
            "<div class=\"section\">" +
            "No remediation actions were generated." +
            "</div>");

        return;
    }

    html.AppendLine(
        "<div class=\"section\">");

    html.AppendLine(
        "<strong>Remediation execution policy</strong>");

    html.AppendLine(
        "<p>" +
        "CloudLens generates remediation guidance only. " +
        "No Azure resource changes are executed automatically. " +
        "Actions marked as Review Required must be validated " +
        "against workload, security and architectural dependencies " +
        "before execution." +
        "</p>");

    html.AppendLine(
        "</div>");

    html.AppendLine(
        "<table>");

    html.AppendLine(
        "<tr>" +
        "<th>Severity</th>" +
        "<th>Category</th>" +
        "<th>Rule</th>" +
        "<th>Resource</th>" +
        "<th>Action</th>" +
        "<th>Status</th>" +
        "<th>Command</th>" +
        "</tr>");

    foreach (var action in actions)
    {
        html.AppendLine(
            "<tr>");

        html.AppendLine(
            $"<td class=\"{action.Severity.ToString().ToLowerInvariant()}\">" +
            $"{action.Severity}</td>");

        html.AppendLine(
            $"<td>{Encode(action.Category.ToString())}</td>");

        html.AppendLine(
            $"<td><code>{Encode(action.RuleId)}</code></td>");

        html.AppendLine(
            $"<td>{Encode(action.ResourceName)}<br>" +
            $"<code>{Encode(action.ResourceType)}</code>");

        if (!string.IsNullOrWhiteSpace(
                action.ResourceId))
        {
            html.AppendLine(
                $"<br><code>{Encode(action.ResourceId)}</code>");
        }

        html.AppendLine(
            "</td>");

        html.AppendLine(
            $"<td>{Encode(action.Action)}</td>");

        var statusClass =
            action.Status
                .ToString()
                .ToLowerInvariant();

        html.AppendLine(
            $"<td class=\"{statusClass}\">" +
            $"{Encode(GetRemediationStatusLabel(action.Status))}</td>");

        if (!string.IsNullOrWhiteSpace(
                action.Command))
        {
            html.AppendLine(
                "<td>" +
                $"<code class=\"command\">" +
                $"{Encode(action.Command)}" +
                "</code>" +
                "</td>");
        }
        else
        {
            html.AppendLine(
                "<td>" +
                "<span class=\"muted\">" +
                "No CLI command generated" +
                "</span>" +
                "</td>");
        }

        html.AppendLine(
            "</tr>");
    }

    html.AppendLine(
        "</table>");
}

private static string GetRemediationStatusLabel(
    RemediationStatus status)
{
    return status switch
    {
        RemediationStatus.Ready =>
            "Ready",

        RemediationStatus.ReviewRequired =>
            "Review Required",

        RemediationStatus.NotAutomatable =>
            "Not Automatable",

        _ =>
            status.ToString()
    };
}

private static void AppendMetrics(
    StringBuilder html,
    TenantScanResult assessment)
{
    html.AppendLine(
        "<h2>Metrics</h2>");

    if (assessment.AllMetricProfiles.Count == 0)
    {
        html.AppendLine(
            "<div class=\"section\">" +
            "No metric profiles were collected." +
            "</div>");

        return;
    }

    html.AppendLine(
        "<table>");

    html.AppendLine(
        "<tr>" +
        "<th>Resource</th>" +
        "<th>Type</th>" +
        "<th>Metric</th>" +
        "<th>Average</th>" +
        "<th>Minimum</th>" +
        "<th>Maximum</th>" +
        "<th>Samples</th>" +
        "<th>Days</th>" +
        "</tr>");

    foreach (var metric in
             assessment.AllMetricProfiles
                .OrderBy(
                    x => x.ResourceType,
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    x => x.ResourceName,
                    StringComparer.OrdinalIgnoreCase)
                .ThenBy(
                    x => x.MetricName,
                    StringComparer.OrdinalIgnoreCase))
    {
        html.AppendLine(
            "<tr>");

        html.AppendLine(
            $"<td>{Encode(metric.ResourceName)}</td>");

        html.AppendLine(
            $"<td><code>{Encode(metric.ResourceType)}</code></td>");

        html.AppendLine(
            $"<td>{Encode(metric.MetricDisplayName ?? metric.MetricName)}</td>");

        html.AppendLine(
            $"<td>{metric.Average:F2} {Encode(metric.Unit)}</td>");

        html.AppendLine(
            $"<td>{metric.Minimum:F2}</td>");

        html.AppendLine(
            $"<td>{metric.Maximum:F2}</td>");

        html.AppendLine(
            $"<td>{metric.SampleCount}</td>");

        html.AppendLine(
            $"<td>{metric.LookbackDays}</td>");

        html.AppendLine(
            "</tr>");
    }

    html.AppendLine(
        "</table>");
}

private static void AppendCard(
    StringBuilder html,
    string title,
    string value)
{
    html.AppendLine(
        "<div class=\"card\">");

    html.AppendLine(
        $"<div class=\"muted\">{Encode(title)}</div>");

    html.AppendLine(
        $"<div class=\"value\">{Encode(value)}</div>");

    html.AppendLine(
        "</div>");
}

private static string GetScoreDescription(
    int score)
{
    return score switch
    {
        >= 90 =>
            "The environment presents a strong overall posture.",

        >= 75 =>
            "The environment is generally healthy, with some areas requiring attention.",

        >= 60 =>
            "Several areas require improvement and should be prioritized according to business impact.",

        >= 40 =>
            "The assessment identified significant risks requiring structured remediation planning.",

        _ =>
            "The environment presents significant risks across multiple assessment areas."
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

private static string Encode(
    string? value)
{
    return WebUtility.HtmlEncode(
        value ?? string.Empty);
}
}
