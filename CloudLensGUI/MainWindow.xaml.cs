#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Windows;
using System.Windows.Input;
using CloudLens.Core;
using CloudLens.Core.Azure;
using Microsoft.Win32;

namespace CloudLensGUI;

public partial class MainWindow : Window
{
    private readonly HttpClient _http = new();

    private AzureCollector? _collector;

    private List<AzureSubscription> _subscriptions = [];

    private ScanResult? _result;

    private CloudLens.Core.TenantScanResult? _tenantResult;

    private string? _tenantId;

    private string? _accessToken;

    private bool _authenticated;

    public MainWindow()
    {
        InitializeComponent();

        Subscription.Items.Add(
            "Accedere prima con Microsoft");

        Subscription.SelectedIndex = 0;

        ClearIntelligence();
    }

    private void Demo_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            var demo =
                DemoAnalyzer.CreateDemo();

            LoadResult(
                demo);

            StatusPanel.Visibility =
                Visibility.Visible;

            StatusText.Text =
                "Demo caricata. È possibile esportare il risultato in HTML, JSON o Excel.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "CloudLens — errore demo",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private async void Login_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(
                    Tenant.Text))
            {
                MessageBox.Show(
                    "Inserire il Tenant ID.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            SetBusy(true);

            StatusPanel.Visibility =
                Visibility.Visible;

            StatusText.Text =
                "Apertura autenticazione Microsoft...";

            Progress.IsIndeterminate =
                false;

            Progress.Value =
                10;

            _tenantId =
                Tenant.Text.Trim();

            _collector ??=
                new AzureCollector(
                    _http);

            var authenticator =
                new AzureAuthenticator(
                    _http);

            _accessToken =
                await authenticator
                    .GetInteractiveAccessTokenAsync(
                        _tenantId);

            Progress.Value =
                50;

            StatusText.Text =
                "Autenticazione completata. Recupero subscription...";

            var client =
                new AzureResourceClient(
                    _http,
                    _accessToken);

            _subscriptions =
                await client.GetSubscriptionsAsync();

            Subscription.Items.Clear();

            foreach (var subscription in
                     _subscriptions)
            {
                Subscription.Items.Add(
                    $"{subscription.Name} ({subscription.Id})");
            }

            if (_subscriptions.Count == 0)
            {
                _authenticated =
                    false;

                _accessToken =
                    null;

                Progress.Value =
                    100;

                StatusText.Text =
                    "Autenticazione riuscita, ma nessuna subscription è accessibile.";

                MessageBox.Show(
                    "L'autenticazione Microsoft è riuscita, " +
                    "ma il tuo account non vede alcuna subscription Azure.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            Subscription.SelectedIndex =
                0;

            _authenticated =
                true;

            Progress.Value =
                100;

            StatusText.Text =
                $"Autenticazione riuscita. " +
                $"{_subscriptions.Count} subscription disponibili.";
        }
        catch (Exception ex)
        {
            _authenticated =
                false;

            _accessToken =
                null;

            StatusText.Text =
                "Autenticazione fallita.";

            MessageBox.Show(
                ex.Message,
                "CloudLens — errore autenticazione",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Run_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            if (!_authenticated ||
                string.IsNullOrWhiteSpace(
                    _accessToken))
            {
                MessageBox.Show(
                    "Prima effettuare l'accesso con Microsoft.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            if (_subscriptions.Count == 0)
            {
                MessageBox.Show(
                    "Non sono disponibili subscription Azure.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            if (string.IsNullOrWhiteSpace(
                    _tenantId))
            {
                MessageBox.Show(
                    "Tenant ID non disponibile.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            SetBusy(true);

            StatusPanel.Visibility =
                Visibility.Visible;

            StatusText.Text =
                $"Avvio scansione completa del tenant " +
                $"({_subscriptions.Count} subscription)...";

            Progress.IsIndeterminate =
                true;

            _collector ??=
                new AzureCollector(
                    _http);

            _tenantResult =
                await _collector
                    .ScanTenantInteractiveAsync(
                        _tenantId,
                        _accessToken,
                        _subscriptions);

            Progress.IsIndeterminate =
                false;

            Progress.Value =
                100;

            StatusText.Text =
                $"Assessment tenant completato: " +
                $"{_tenantResult.TotalResources} risorse analizzate.";

            LoadTenantResult(
                _tenantResult);
        }
        catch (Exception ex)
        {
            Progress.IsIndeterminate =
                false;

            Progress.Value =
                0;

            StatusText.Text =
                "Assessment fallito.";

            MessageBox.Show(
                ex.Message,
                "CloudLens — errore assessment",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ExportReport_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!TryGetExportAssessment(
                out var assessment))
        {
            return;
        }

        var dialog =
            new SaveFileDialog
            {
                Title =
                    "Salva CloudLens Assessment Report",

                Filter =
                    "HTML report (*.html)|*.html",

                FileName =
                    $"CloudLens-Assessment-" +
                    $"{DateTime.Now:yyyyMMdd-HHmmss}.html"
            };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var html =
                AssessmentReportBuilder.BuildHtml(
                    assessment);

            File.WriteAllText(
                dialog.FileName,
                html);

            MessageBox.Show(
                $"Report salvato:\n{dialog.FileName}",
                "CloudLens",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "CloudLens — errore export report",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ExportJson_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!TryGetExportAssessment(
                out var assessment))
        {
            return;
        }

        var dialog =
            new SaveFileDialog
            {
                Title =
                    "Esporta CloudLens Assessment JSON",

                Filter =
                    "JSON (*.json)|*.json",

                FileName =
                    $"CloudLens-Assessment-" +
                    $"{DateTime.Now:yyyyMMdd-HHmmss}.json"
            };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            AssessmentJsonExporter.ExportToFile(
                assessment,
                dialog.FileName);

            MessageBox.Show(
                $"Export JSON completato:\n{dialog.FileName}",
                "CloudLens",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "CloudLens — errore export JSON",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ExportExcel_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!TryGetExportAssessment(
                out var assessment))
        {
            return;
        }

        var dialog =
            new SaveFileDialog
            {
                Title =
                    "Esporta CloudLens Assessment Excel",

                Filter =
                    "Excel Workbook (*.xlsx)|*.xlsx",

                FileName =
                    $"CloudLens-Assessment-" +
                    $"{DateTime.Now:yyyyMMdd-HHmmss}.xlsx"
            };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            AssessmentExcelExporter.Export(
                assessment,
                dialog.FileName);

            MessageBox.Show(
                $"Export Excel completato:\n{dialog.FileName}",
                "CloudLens",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "CloudLens — errore export Excel",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private bool TryGetExportAssessment(
        out CloudLens.Core.TenantScanResult assessment)
    {
        if (_tenantResult != null)
        {
            assessment =
                _tenantResult;

            return true;
        }

        if (_result != null)
        {
            assessment =
                BuildTenantResultFromSingleResult(
                    _result);

            return true;
        }

        assessment =
            null!;

        MessageBox.Show(
            "Eseguire prima un assessment o caricare la demo.",
            "CloudLens",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);

        return false;
    }

    private CloudLens.Core.TenantScanResult
        BuildTenantResultFromSingleResult(
            ScanResult result)
    {
        var subscription =
            new AzureSubscription(
                result.SubscriptionName,
                result.SubscriptionId);

        return new CloudLens.Core.TenantScanResult
        {
            TenantId =
                _tenantId ?? "demo",

            StartedAt =
                DateTimeOffset.Now,

            CompletedAt =
                DateTimeOffset.Now,

            Subscriptions =
            [
                new SubscriptionAssessment(
                    subscription,
                    result,
                    [])
            ]
        };
    }

    private void SetBusy(
        bool busy)
    {
        Mouse.OverrideCursor =
            busy
                ? Cursors.Wait
                : null;

        LoginButton.IsEnabled =
            !busy;

        RunAssessmentButton.IsEnabled =
            !busy;

        DemoButton.IsEnabled =
            !busy;

        ExportReportButton.IsEnabled =
            !busy &&
            (_tenantResult != null ||
             _result != null);

        ExportJsonButton.IsEnabled =
            !busy &&
            (_tenantResult != null ||
             _result != null);

        ExportExcelButton.IsEnabled =
            !busy &&
            (_tenantResult != null ||
             _result != null);

        Tenant.IsEnabled =
            !busy;

        Subscription.IsEnabled =
            !busy;
    }

    private void LoadResult(
        ScanResult result)
    {
        _result =
            result;

        _tenantResult =
            null;

        Results.Visibility =
            Visibility.Visible;

        Score.Text =
            $"{result.Score}/100";

        FindingCount.Text =
            result.Findings.Count.ToString();

        var saving =
            result.Findings.Sum(
                x =>
                    x.MonthlySavingEur);

        Saving.Text =
            $"€ {saving:N2}";

        SavingYear.Text =
            $"€ {saving * 12:N2}";

        FindingsGrid.ItemsSource =
            result.Findings;

        MetricsGrid.ItemsSource =
            result.MetricProfiles;

        ClearIntelligence();

        ExportReportButton.IsEnabled =
            false;

        ExportJsonButton.IsEnabled =
            true;

        ExportExcelButton.IsEnabled =
            true;
    }

    private void LoadTenantResult(
        CloudLens.Core.TenantScanResult result)
    {
        _tenantResult =
            result;

        _result =
            null;

        Results.Visibility =
            Visibility.Visible;

        Score.Text =
            $"{result.OverallScore}/100";

        FindingCount.Text =
            result.AllFindings.Count.ToString();

        var saving =
            result.AllFindings.Sum(
                x =>
                    x.MonthlySavingEur);

        Saving.Text =
            $"€ {saving:N2}";

        SavingYear.Text =
            $"€ {saving * 12:N2}";

        FindingsGrid.ItemsSource =
            result.AllFindings;

        MetricsGrid.ItemsSource =
            result.AllMetricProfiles;

        LoadIntelligence(
            result.Intelligence);

        ExportReportButton.IsEnabled =
            true;

        ExportJsonButton.IsEnabled =
            true;

        ExportExcelButton.IsEnabled =
            true;
    }

    private void LoadIntelligence(
        CloudLens.Core.Analysis.AssessmentIntelligence intelligence)
    {
        IntelligenceTotalRisks.Text =
            intelligence.TotalRisks.ToString();

        IntelligenceP0.Text =
            intelligence.P0Count.ToString();

        IntelligenceP1.Text =
            intelligence.P1Count.ToString();

        IntelligenceP2.Text =
            intelligence.P2Count.ToString();

        IntelligenceP3.Text =
            intelligence.P3Count.ToString();

        IntelligenceSaving.Text =
            $"€ {intelligence.PotentialMonthlySavingEur:N2}";

        QuickWinsGrid.ItemsSource =
            intelligence.QuickWins;

        SystemicRisksGrid.ItemsSource =
            intelligence.SystemicRisks;

        PrioritizedRisksGrid.ItemsSource =
            intelligence.Risks;

        RoadmapGrid.ItemsSource =
            intelligence.Roadmap;
    }

    private void ClearIntelligence()
    {
        IntelligenceTotalRisks.Text =
            "0";

        IntelligenceP0.Text =
            "0";

        IntelligenceP1.Text =
            "0";

        IntelligenceP2.Text =
            "0";

        IntelligenceP3.Text =
            "0";

        IntelligenceSaving.Text =
            "€ 0.00";

        QuickWinsGrid.ItemsSource =
            null;

        SystemicRisksGrid.ItemsSource =
            null;

        PrioritizedRisksGrid.ItemsSource =
            null;

        RoadmapGrid.ItemsSource =
            null;
    }
}