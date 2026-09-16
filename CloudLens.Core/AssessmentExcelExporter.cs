using CloudLens.Core.Analysis;
using ClosedXML.Excel;

namespace CloudLens.Core;

public static class AssessmentExcelExporter
{
    public static void Export(
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

        var document =
            AssessmentJsonExporter.BuildDocument(
                assessment);

        using var workbook =
            new XLWorkbook();

        CreateSummarySheet(
            workbook,
            document);

        CreateRiskOverviewSheet(
            workbook,
            document);

        CreateIntelligenceSheet(
            workbook,
            document);

        CreateSubscriptionsSheet(
            workbook,
            document);

        CreateInventorySheet(
            workbook,
            document);

        CreateFindingsSheet(
            workbook,
            document);

        CreateRemediationSheet(
            workbook,
            document);

        CreateMetricsSheet(
            workbook,
            document);

        workbook.SaveAs(filePath);
    }

    private static void CreateSummarySheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Summary");

        sheet.Cell("A1").Value =
            "CloudLens Azure Assessment";

        sheet.Cell("A1").Style.Font.Bold =
            true;

        sheet.Cell("A1").Style.Font.FontSize =
            18;

        sheet.Range("A1:B1")
            .Merge();

        var rows =
            new[]
            {
                ("Tenant ID", document.TenantId),
                ("Export Version", document.ExportVersion),
                ("Started At", document.StartedAt.ToString("u")),
                ("Completed At", document.CompletedAt.ToString("u")),
                ("Overall Score", document.OverallScore.ToString()),
                ("Subscriptions", document.Subscriptions.Count.ToString()),
                ("Resources", document.TotalResources.ToString()),
                ("Resource Types", document.TotalResourceTypes.ToString()),
                ("Relationships", document.TotalRelationships.ToString()),
                ("Enriched Resources", document.EnrichedResources.ToString()),
                ("Enrichment Coverage", $"{document.EnrichmentCoveragePercent:F1}%"),
                ("Metric Profiles", document.TotalMetricProfiles.ToString()),
                ("Critical Findings", document.CriticalFindings.ToString()),
                ("High Findings", document.HighFindings.ToString()),
                ("Medium Findings", document.MediumFindings.ToString()),
                ("Low Findings", document.LowFindings.ToString()),
                ("Total Findings", document.Findings.Count.ToString()),
                ("Total Remediations", document.Remediations.Count.ToString()),
                ("Intelligence Risks", document.Intelligence.TotalRisks.ToString()),
                ("P0 Risks", document.Intelligence.P0Count.ToString()),
                ("P1 Risks", document.Intelligence.P1Count.ToString()),
                ("P2 Risks", document.Intelligence.P2Count.ToString()),
                ("P3 Risks", document.Intelligence.P3Count.ToString()),
                ("Quick Wins", document.Intelligence.QuickWinCount.ToString()),
                ("Systemic Risks", document.Intelligence.SystemicRiskCount.ToString()),
                ("Potential Monthly Saving EUR",
                    document.Intelligence.PotentialMonthlySavingEur
                        .ToString("F2"))
            };

        sheet.Cell("A3").Value =
            "Assessment";

        sheet.Cell("A3").Style.Font.Bold =
            true;

        sheet.Cell("B3").Value =
            "Value";

        sheet.Cell("B3").Style.Font.Bold =
            true;

        var row =
            4;

        foreach (var item in rows)
        {
            sheet.Cell(row, 1).Value =
                item.Item1;

            sheet.Cell(row, 2).Value =
                item.Item2;

            row++;
        }

        row += 2;

        sheet.Cell(row, 1).Value =
            "Category";

        sheet.Cell(row, 2).Value =
            "Score";

        StyleHeader(
            sheet.Range(row, 1, row, 2));

        row++;

        foreach (var category in
                 Enum.GetValues<Category>())
        {
            sheet.Cell(row, 1).Value =
                category.ToString();

            sheet.Cell(row, 2).Value =
                document.ScoresByCategory
                    .TryGetValue(
                        category,
                        out var score)
                    ? score
                    : 100;

            row++;
        }

        sheet.Columns()
            .AdjustToContents();

        sheet.Column(1).Width =
            Math.Min(
                50,
                Math.Max(
                    20,
                    sheet.Column(1).Width));

        sheet.Column(2).Width =
            Math.Min(
                50,
                Math.Max(
                    20,
                    sheet.Column(2).Width));
    }

    private static void CreateRiskOverviewSheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Risk Overview");

        sheet.Cell("A1").Value =
            "CloudLens Risk Overview";

        sheet.Cell("A1").Style.Font.Bold =
            true;

        sheet.Cell("A1").Style.Font.FontSize =
            18;

        sheet.Range("A1:H1")
            .Merge();

        sheet.Cell("A3").Value =
            "Severity Overview";

        sheet.Cell("A3").Style.Font.Bold =
            true;

        var severityHeaders =
            new[]
            {
                "Severity",
                "Findings"
            };

        WriteHeader(
            sheet,
            severityHeaders,
            4);

        var severityRow =
            5;

        foreach (var item in document.Insights.Severity
                     .OrderBy(
                         x => SeverityOrder(x.Severity)))
        {
            sheet.Cell(severityRow, 1).Value =
                item.Severity.ToString();

            sheet.Cell(severityRow, 2).Value =
                item.Count;

            severityRow++;
        }

        var categoryStartRow =
            severityRow + 2;

        sheet.Cell(categoryStartRow, 1).Value =
            "Category Risk Overview";

        sheet.Cell(categoryStartRow, 1)
            .Style.Font.Bold =
            true;

        var categoryHeaders =
            new[]
            {
                "Category",
                "Score",
                "Findings",
                "Critical",
                "High",
                "Medium",
                "Low"
            };

        WriteHeader(
            sheet,
            categoryHeaders,
            categoryStartRow + 1);

        var categoryRow =
            categoryStartRow + 2;

        foreach (var item in document.Insights.Categories
                     .OrderBy(
                         x => x.Score)
                     .ThenByDescending(
                         x => x.FindingCount))
        {
            sheet.Cell(categoryRow, 1).Value =
                item.Category.ToString();

            sheet.Cell(categoryRow, 2).Value =
                item.Score;

            sheet.Cell(categoryRow, 3).Value =
                item.FindingCount;

            sheet.Cell(categoryRow, 4).Value =
                item.CriticalCount;

            sheet.Cell(categoryRow, 5).Value =
                item.HighCount;

            sheet.Cell(categoryRow, 6).Value =
                item.MediumCount;

            sheet.Cell(categoryRow, 7).Value =
                item.LowCount;

            categoryRow++;
        }

        var riskStartRow =
            categoryRow + 2;

        sheet.Cell(riskStartRow, 1).Value =
            "Top Risks";

        sheet.Cell(riskStartRow, 1)
            .Style.Font.Bold =
            true;

        var riskHeaders =
            new[]
            {
                "Severity",
                "Category",
                "Rule",
                "Title",
                "Resource",
                "Resource Type",
                "Impact",
                "Recommendation",
                "Monthly Saving EUR"
            };

        WriteHeader(
            sheet,
            riskHeaders,
            riskStartRow + 1);

        var riskRow =
            riskStartRow + 2;

        foreach (var risk in document.Insights.TopRisks)
        {
            sheet.Cell(riskRow, 1).Value =
                risk.Severity.ToString();

            sheet.Cell(riskRow, 2).Value =
                risk.Category.ToString();

            sheet.Cell(riskRow, 3).Value =
                risk.RuleId;

            sheet.Cell(riskRow, 4).Value =
                risk.Title;

            sheet.Cell(riskRow, 5).Value =
                risk.ResourceName;

            sheet.Cell(riskRow, 6).Value =
                risk.ResourceType;

            sheet.Cell(riskRow, 7).Value =
                risk.Impact;

            sheet.Cell(riskRow, 8).Value =
                risk.Recommendation;

            sheet.Cell(riskRow, 9).Value =
                risk.MonthlySavingEur;

            sheet.Cell(riskRow, 9)
                .Style.NumberFormat
                .Format =
                "€ #,##0.00";

            riskRow++;
        }

        var remediationStartRow =
            riskRow + 2;

        sheet.Cell(remediationStartRow, 1).Value =
            "Remediation Overview";

        sheet.Cell(remediationStartRow, 1)
            .Style.Font.Bold =
            true;

        var remediationHeaders =
            new[]
            {
                "Status",
                "Actions",
                "Critical",
                "High"
            };

        WriteHeader(
            sheet,
            remediationHeaders,
            remediationStartRow + 1);

        var remediationRow =
            remediationStartRow + 2;

        foreach (var item in document.Insights.Remediation)
        {
            sheet.Cell(remediationRow, 1).Value =
                GetRemediationStatusLabel(
                    item.Status);

            sheet.Cell(remediationRow, 2).Value =
                item.Count;

            sheet.Cell(remediationRow, 3).Value =
                item.CriticalCount;

            sheet.Cell(remediationRow, 4).Value =
                item.HighCount;

            remediationRow++;
        }

        var coverageStartRow =
            remediationRow + 2;

        sheet.Cell(coverageStartRow, 1).Value =
            "Assessment Coverage";

        sheet.Cell(coverageStartRow, 1)
            .Style.Font.Bold =
            true;

        var coverageHeaders =
            new[]
            {
                "Metric",
                "Value"
            };

        WriteHeader(
            sheet,
            coverageHeaders,
            coverageStartRow + 1);

        var coverage =
            document.Insights.Coverage;

        var coverageRows =
            new[]
            {
                ("Total Resources",
                    coverage.TotalResources.ToString()),

                ("Enriched Resources",
                    coverage.EnrichedResources.ToString()),

                ("Enrichment Coverage",
                    $"{coverage.EnrichmentCoveragePercent:F1}%"),

                ("Total Resource Types",
                    coverage.TotalResourceTypes.ToString()),

                ("Supported Resource Types",
                    coverage.SupportedResourceTypes.ToString()),

                ("Generic Resource Types",
                    coverage.GenericResourceTypes.ToString()),

                ("Unsupported Resource Types",
                    coverage.UnsupportedResourceTypes.ToString()),

                ("Resource Type Coverage",
                    $"{coverage.ResourceTypeCoveragePercent:F1}%"),

                ("Specialized Analyzer Coverage",
                    $"{coverage.SpecializedAnalyzerCoveragePercent:F1}%"),

                ("Metric Capable Resources",
                    coverage.MetricCapableResources.ToString()),

                ("Metric Profiles",
                    coverage.MetricProfiles.ToString())
            };

        var coverageRow =
            coverageStartRow + 2;

        foreach (var item in coverageRows)
        {
            sheet.Cell(coverageRow, 1).Value =
                item.Item1;

            sheet.Cell(coverageRow, 2).Value =
                item.Item2;

            coverageRow++;
        }

        sheet.Columns()
            .AdjustToContents();

        sheet.Column(1).Width =
            Math.Min(
                30,
                Math.Max(
                    18,
                    sheet.Column(1).Width));

        sheet.Column(4).Width = 35;
        sheet.Column(7).Width = 45;
        sheet.Column(8).Width = 50;

        sheet.SheetView.FreezeRows(4);
    }

    private static void CreateIntelligenceSheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Intelligence");

        sheet.Cell("A1").Value =
            "CloudLens Assessment Intelligence";

        sheet.Cell("A1").Style.Font.Bold =
            true;

        sheet.Cell("A1").Style.Font.FontSize =
            18;

        sheet.Range("A1:J1")
            .Merge();

        var summaryRows =
            new[]
            {
                ("Total Risks",
                    document.Intelligence.TotalRisks.ToString()),

                ("P0 Risks",
                    document.Intelligence.P0Count.ToString()),

                ("P1 Risks",
                    document.Intelligence.P1Count.ToString()),

                ("P2 Risks",
                    document.Intelligence.P2Count.ToString()),

                ("P3 Risks",
                    document.Intelligence.P3Count.ToString()),

                ("Quick Wins",
                    document.Intelligence.QuickWinCount.ToString()),

                ("Systemic Risks",
                    document.Intelligence.SystemicRiskCount.ToString()),

                ("Potential Monthly Saving EUR",
                    document.Intelligence.PotentialMonthlySavingEur
                        .ToString("F2"))
            };

        sheet.Cell("A3").Value =
            "Intelligence Summary";

        sheet.Cell("A3").Style.Font.Bold =
            true;

        WriteHeader(
            sheet,
            new[]
            {
                "Metric",
                "Value"
            },
            4);

        var summaryRow = 5;

        foreach (var item in summaryRows)
        {
            sheet.Cell(summaryRow, 1).Value =
                item.Item1;

            sheet.Cell(summaryRow, 2).Value =
                item.Item2;

            summaryRow++;
        }

        var riskStartRow =
            summaryRow + 2;

        sheet.Cell(riskStartRow, 1).Value =
            "Prioritized Risks";

        sheet.Cell(riskStartRow, 1)
            .Style.Font.Bold =
            true;

        var riskHeaders =
            new[]
            {
                "Priority",
                "Score",
                "Classification",
                "Severity",
                "Category",
                "Rule",
                "Title",
                "Resource",
                "Resource Type",
                "Impact",
                "Effort",
                "Quick Win",
                "Systemic",
                "Monthly Saving EUR",
                "Rationale"
            };

        WriteHeader(
            sheet,
            riskHeaders,
            riskStartRow + 1);

        var riskRow =
            riskStartRow + 2;

        foreach (var risk in document.Intelligence.Risks
                     .OrderBy(x => x.Priority)
                     .ThenByDescending(x => x.PriorityScore))
        {
            sheet.Cell(riskRow, 1).Value =
                risk.Priority.ToString();

            sheet.Cell(riskRow, 2).Value =
                risk.PriorityScore;

            sheet.Cell(riskRow, 3).Value =
                risk.Classification.ToString();

            sheet.Cell(riskRow, 4).Value =
                risk.Severity.ToString();

            sheet.Cell(riskRow, 5).Value =
                risk.Category.ToString();

            sheet.Cell(riskRow, 6).Value =
                risk.RuleId;

            sheet.Cell(riskRow, 7).Value =
                risk.Title;

            sheet.Cell(riskRow, 8).Value =
                risk.ResourceName;

            sheet.Cell(riskRow, 9).Value =
                risk.ResourceType;

            sheet.Cell(riskRow, 10).Value =
                risk.ImpactScore;

            sheet.Cell(riskRow, 11).Value =
                risk.EffortScore;

            sheet.Cell(riskRow, 12).Value =
                risk.IsQuickWin;

            sheet.Cell(riskRow, 13).Value =
                risk.IsSystemic;

            sheet.Cell(riskRow, 14).Value =
                risk.MonthlySavingEur;

            sheet.Cell(riskRow, 14)
                .Style.NumberFormat
                .Format =
                "€ #,##0.00";

            sheet.Cell(riskRow, 15).Value =
                risk.Rationale;

            riskRow++;
        }

        var quickWinStartRow =
            riskRow + 2;

        sheet.Cell(quickWinStartRow, 1).Value =
            "Quick Wins";

        sheet.Cell(quickWinStartRow, 1)
            .Style.Font.Bold =
            true;

        var quickWinHeaders =
            new[]
            {
                "Priority",
                "Score",
                "Severity",
                "Category",
                "Title",
                "Resource",
                "Resource Type",
                "Impact",
                "Effort",
                "Monthly Saving EUR",
                "Rationale"
            };

        WriteHeader(
            sheet,
            quickWinHeaders,
            quickWinStartRow + 1);

        var quickWinRow =
            quickWinStartRow + 2;

        foreach (var item in document.Intelligence.QuickWins
                     .OrderBy(x => x.Priority)
                     .ThenByDescending(x => x.PriorityScore))
        {
            sheet.Cell(quickWinRow, 1).Value =
                item.Priority.ToString();

            sheet.Cell(quickWinRow, 2).Value =
                item.PriorityScore;

            sheet.Cell(quickWinRow, 3).Value =
                item.Severity.ToString();

            sheet.Cell(quickWinRow, 4).Value =
                item.Category.ToString();

            sheet.Cell(quickWinRow, 5).Value =
                item.Title;

            sheet.Cell(quickWinRow, 6).Value =
                item.ResourceName;

            sheet.Cell(quickWinRow, 7).Value =
                item.ResourceType;

            sheet.Cell(quickWinRow, 8).Value =
                item.ImpactScore;

            sheet.Cell(quickWinRow, 9).Value =
                item.EffortScore;

            sheet.Cell(quickWinRow, 10).Value =
                item.MonthlySavingEur;

            sheet.Cell(quickWinRow, 10)
                .Style.NumberFormat
                .Format =
                "€ #,##0.00";

            sheet.Cell(quickWinRow, 11).Value =
                item.Rationale;

            quickWinRow++;
        }

        var systemicStartRow =
            quickWinRow + 2;

        sheet.Cell(systemicStartRow, 1).Value =
            "Systemic Risks";

        sheet.Cell(systemicStartRow, 1)
            .Style.Font.Bold =
            true;

        var systemicHeaders =
            new[]
            {
                "Priority",
                "Score",
                "Severity",
                "Category",
                "Title",
                "Findings",
                "Affected Resources",
                "Description",
                "Finding IDs"
            };

        WriteHeader(
            sheet,
            systemicHeaders,
            systemicStartRow + 1);

        var systemicRow =
            systemicStartRow + 2;

        foreach (var item in document.Intelligence.SystemicRisks
                     .OrderBy(x => x.Priority)
                     .ThenByDescending(x => x.PriorityScore))
        {
            sheet.Cell(systemicRow, 1).Value =
                item.Priority.ToString();

            sheet.Cell(systemicRow, 2).Value =
                item.PriorityScore;

            sheet.Cell(systemicRow, 3).Value =
                item.Severity.ToString();

            sheet.Cell(systemicRow, 4).Value =
                item.Category.ToString();

            sheet.Cell(systemicRow, 5).Value =
                item.Title;

            sheet.Cell(systemicRow, 6).Value =
                item.FindingCount;

            sheet.Cell(systemicRow, 7).Value =
                item.AffectedResources;

            sheet.Cell(systemicRow, 8).Value =
                item.Description;

            sheet.Cell(systemicRow, 9).Value =
                string.Join(
                    ", ",
                    item.FindingIds);

            systemicRow++;
        }

        var roadmapStartRow =
            systemicRow + 2;

        sheet.Cell(roadmapStartRow, 1).Value =
            "Remediation Roadmap";

        sheet.Cell(roadmapStartRow, 1)
            .Style.Font.Bold =
            true;

        var roadmapHeaders =
            new[]
            {
                "Priority",
                "Score",
                "Classification",
                "Severity",
                "Category",
                "Title",
                "Impact",
                "Effort",
                "Monthly Saving EUR",
                "Action",
                "Command",
                "Requires Review"
            };

        WriteHeader(
            sheet,
            roadmapHeaders,
            roadmapStartRow + 1);

        var roadmapRow =
            roadmapStartRow + 2;

        foreach (var item in document.Intelligence.Roadmap
                     .OrderBy(x => x.Priority)
                     .ThenByDescending(x => x.PriorityScore))
        {
            sheet.Cell(roadmapRow, 1).Value =
                item.Priority.ToString();

            sheet.Cell(roadmapRow, 2).Value =
                item.PriorityScore;

            sheet.Cell(roadmapRow, 3).Value =
                item.Classification.ToString();

            sheet.Cell(roadmapRow, 4).Value =
                item.Severity.ToString();

            sheet.Cell(roadmapRow, 5).Value =
                item.Category.ToString();

            sheet.Cell(roadmapRow, 6).Value =
                item.Title;

            sheet.Cell(roadmapRow, 7).Value =
                item.ImpactScore;

            sheet.Cell(roadmapRow, 8).Value =
                item.EffortScore;

            sheet.Cell(roadmapRow, 9).Value =
                item.MonthlySavingEur;

            sheet.Cell(roadmapRow, 9)
                .Style.NumberFormat
                .Format =
                "€ #,##0.00";

            sheet.Cell(roadmapRow, 10).Value =
                item.Action;

            sheet.Cell(roadmapRow, 11).Value =
                item.Command ?? "";

            sheet.Cell(roadmapRow, 12).Value =
                item.RequiresReview;

            roadmapRow++;
        }

        sheet.Columns()
            .AdjustToContents();

        sheet.Column(1).Width = 15;
        sheet.Column(2).Width = 12;
        sheet.Column(3).Width = 22;
        sheet.Column(4).Width = 15;
        sheet.Column(5).Width = 18;
        sheet.Column(6).Width = 40;
        sheet.Column(7).Width = 40;
        sheet.Column(8).Width = 35;
        sheet.Column(9).Width = 22;
        sheet.Column(10).Width = 45;
        sheet.Column(11).Width = 60;
        sheet.Column(12).Width = 18;
        sheet.Column(13).Width = 15;
        sheet.Column(14).Width = 22;
        sheet.Column(15).Width = 55;

        sheet.SheetView.FreezeRows(4);
    }

    private static void CreateSubscriptionsSheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Subscriptions");

        var headers =
            new[]
            {
                "Name",
                "Subscription ID",
                "Score",
                "Resources",
                "Resource Types",
                "Findings",
                "Remediations"
            };

        WriteHeader(
            sheet,
            headers);

        var row =
            2;

        foreach (var item in document.Subscriptions)
        {
            sheet.Cell(row, 1).Value =
                item.Name;

            sheet.Cell(row, 2).Value =
                item.Id;

            sheet.Cell(row, 3).Value =
                item.Score;

            sheet.Cell(row, 4).Value =
                item.Resources;

            sheet.Cell(row, 5).Value =
                item.ResourceTypes;

            sheet.Cell(row, 6).Value =
                item.Findings;

            sheet.Cell(row, 7).Value =
                item.Remediations;

            row++;
        }

        FinalizeTable(
            sheet,
            row - 1,
            headers.Length);
    }

    private static void CreateInventorySheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Resource Inventory");

        var headers =
            new[]
            {
                "Resource Type",
                "Count"
            };

        WriteHeader(
            sheet,
            headers);

        var row =
            2;

        foreach (var item in document.ResourceInventory)
        {
            sheet.Cell(row, 1).Value =
                item.ResourceType;

            sheet.Cell(row, 2).Value =
                item.Count;

            row++;
        }

        FinalizeTable(
            sheet,
            row - 1,
            headers.Length);
    }

    private static void CreateFindingsSheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Findings");

        var headers =
            new[]
            {
                "Severity",
                "Category",
                "Rule",
                "Title",
                "Resource",
                "Resource Type",
                "Resource ID",
                "Description",
                "Impact",
                "Recommendation",
                "Monthly Saving EUR",
                "Azure CLI"
            };

        WriteHeader(
            sheet,
            headers);

        var row =
            2;

        foreach (var finding in
                 document.Findings
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
            sheet.Cell(row, 1).Value =
                finding.Severity.ToString();

            sheet.Cell(row, 2).Value =
                finding.Category.ToString();

            sheet.Cell(row, 3).Value =
                finding.RuleId;

            sheet.Cell(row, 4).Value =
                finding.Title;

            sheet.Cell(row, 5).Value =
                finding.ResourceName;

            sheet.Cell(row, 6).Value =
                finding.ResourceType;

            sheet.Cell(row, 7).Value =
                finding.ResourceId ?? "";

            sheet.Cell(row, 8).Value =
                finding.Description;

            sheet.Cell(row, 9).Value =
                finding.Impact;

            sheet.Cell(row, 10).Value =
                finding.Recommendation;

            sheet.Cell(row, 11).Value =
                finding.MonthlySavingEur;

            sheet.Cell(row, 11)
                .Style.NumberFormat
                .Format =
                "€ #,##0.00";

            sheet.Cell(row, 12).Value =
                finding.AzureCli ?? "";

            row++;
        }

        FinalizeTable(
            sheet,
            row - 1,
            headers.Length);

        sheet.Column(8).Width =
            45;

        sheet.Column(9).Width =
            40;

        sheet.Column(10).Width =
            45;

        sheet.Column(12).Width =
            55;
    }

    private static void CreateRemediationSheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Remediation");

        var headers =
            new[]
            {
                "Severity",
                "Category",
                "Rule",
                "Title",
                "Resource",
                "Resource Type",
                "Resource ID",
                "Action Type",
                "Status",
                "Action",
                "Command",
                "Requires Review"
            };

        WriteHeader(
            sheet,
            headers);

        var row =
            2;

        foreach (var action in
                 document.Remediations
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
            sheet.Cell(row, 1).Value =
                action.Severity.ToString();

            sheet.Cell(row, 2).Value =
                action.Category.ToString();

            sheet.Cell(row, 3).Value =
                action.RuleId;

            sheet.Cell(row, 4).Value =
                action.Title;

            sheet.Cell(row, 5).Value =
                action.ResourceName;

            sheet.Cell(row, 6).Value =
                action.ResourceType;

            sheet.Cell(row, 7).Value =
                action.ResourceId ?? "";

            sheet.Cell(row, 8).Value =
                action.ActionType.ToString();

            sheet.Cell(row, 9).Value =
                GetRemediationStatusLabel(
                    action.Status);

            sheet.Cell(row, 10).Value =
                action.Action;

            sheet.Cell(row, 11).Value =
                action.Command ?? "";

            sheet.Cell(row, 12).Value =
                action.RequiresReview;

            row++;
        }

        FinalizeTable(
            sheet,
            row - 1,
            headers.Length);

        sheet.Column(10).Width =
            45;

        sheet.Column(11).Width =
            60;
    }

    private static void CreateMetricsSheet(
        XLWorkbook workbook,
        AssessmentExportDocument document)
    {
        var sheet =
            workbook.Worksheets.Add(
                "Metrics");

        var headers =
            new[]
            {
                "Resource",
                "Resource ID",
                "Resource Type",
                "Metric",
                "Display Name",
                "Unit",
                "Namespace",
                "Average",
                "Minimum",
                "Maximum",
                "Samples",
                "Lookback Days"
            };

        WriteHeader(
            sheet,
            headers);

        var row =
            2;

        foreach (var metric in
                 document.Metrics
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
            sheet.Cell(row, 1).Value =
                metric.ResourceName;

            sheet.Cell(row, 2).Value =
                metric.ResourceId;

            sheet.Cell(row, 3).Value =
                metric.ResourceType;

            sheet.Cell(row, 4).Value =
                metric.MetricName;

            sheet.Cell(row, 5).Value =
                metric.MetricDisplayName ?? "";

            sheet.Cell(row, 6).Value =
                metric.Unit ?? "";

            sheet.Cell(row, 7).Value =
                metric.MetricNamespace ?? "";

            sheet.Cell(row, 8).Value =
                metric.Average;

            sheet.Cell(row, 9).Value =
                metric.Minimum;

            sheet.Cell(row, 10).Value =
                metric.Maximum;

            sheet.Cell(row, 11).Value =
                metric.SampleCount;

            sheet.Cell(row, 12).Value =
                metric.LookbackDays;

            row++;
        }

        FinalizeTable(
            sheet,
            row - 1,
            headers.Length);
    }

    private static void WriteHeader(
        IXLWorksheet sheet,
        IReadOnlyList<string> headers)
    {
        WriteHeader(
            sheet,
            headers,
            1);
    }

    private static void WriteHeader(
        IXLWorksheet sheet,
        IReadOnlyList<string> headers,
        int row)
    {
        for (var index = 0;
             index < headers.Count;
             index++)
        {
            sheet.Cell(
                    row,
                    index + 1)
                .Value =
                headers[index];
        }

        StyleHeader(
            sheet.Range(
                row,
                1,
                row,
                headers.Count));
    }

    private static void StyleHeader(
        IXLRange range)
    {
        range.Style.Font.Bold =
            true;

        range.Style.Alignment.Horizontal =
            XLAlignmentHorizontalValues.Center;

        range.Style.Alignment.Vertical =
            XLAlignmentVerticalValues.Center;

        range.Style.Alignment.WrapText =
            true;
    }

    private static void FinalizeTable(
        IXLWorksheet sheet,
        int lastRow,
        int columnCount)
    {
        if (lastRow < 1)
        {
            return;
        }

        var range =
            sheet.Range(
                1,
                1,
                lastRow,
                columnCount);

        range.Style.Alignment.Vertical =
            XLAlignmentVerticalValues.Top;

        range.Style.Alignment.WrapText =
            true;

        sheet.SheetView.FreezeRows(1);

        sheet.Columns()
            .AdjustToContents();

        for (var column = 1;
             column <= columnCount;
             column++)
        {
            if (sheet.Column(column).Width > 60)
            {
                sheet.Column(column).Width =
                    60;
            }
        }

        if (lastRow > 1)
        {
            sheet.AutoFilter
                .Clear();

            sheet.Range(
                    1,
                    1,
                    lastRow,
                    columnCount)
                .SetAutoFilter();
        }
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
}