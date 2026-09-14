#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CloudLens.Core;
using CloudLens.Core.Analysis;
using CloudLens.Core.Azure;
using Microsoft.Win32;

namespace CloudLensGUI;

public partial class MainWindow : Window
{
private readonly HttpClient _http = new();

private AzureCollector? _collector;

private List<AzureSubscription> _subscriptions = [];

private ScanResult? _result;

private TenantScanResult? _tenantResult;

private string? _tenantId;

private string? _accessToken;

private bool _authenticated;

public MainWindow()
{
    InitializeComponent();

    Subscription.Items.Add(
        "Accedere prima con Microsoft");

    Subscription.SelectedIndex = 0;
}


private void Demo_Click(
    object sender,
    RoutedEventArgs e)
{
    LoadResult(
        DemoAnalyzer.CreateDemo());
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

        Progress.IsIndeterminate = false;
        Progress.Value = 10;

        _tenantId =
            Tenant.Text.Trim();

        _collector ??=
            new AzureCollector(_http);

        var authenticator =
            new AzureAuthenticator(_http);

        _accessToken =
            await authenticator
                .GetInteractiveAccessTokenAsync(
                    _tenantId);

        var client =
            new AzureResourceClient(
                _http,
                _accessToken);

        Progress.Value = 40;

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
            _authenticated = false;
            _accessToken = null;

            Progress.Value = 100;

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

        Subscription.SelectedIndex = 0;

        _authenticated = true;

        Progress.Value = 100;

        StatusText.Text =
            $"Autenticazione riuscita. " +
            $"{_subscriptions.Count} subscription disponibili.";
    }
    catch (Exception ex)
    {
        _authenticated = false;

        _accessToken = null;

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

        Progress.IsIndeterminate = true;

        _collector ??=
            new AzureCollector(_http);

        _tenantResult =
            await _collector
                .ScanTenantInteractiveAsync(
                    _tenantId,
                    _accessToken,
                    _subscriptions);

        Progress.IsIndeterminate = false;
        Progress.Value = 100;

        StatusText.Text =
            $"Assessment tenant completato: " +
            $"{_tenantResult.TotalResources} risorse analizzate.";

        LoadTenantResult(
            _tenantResult);
    }
    catch (Exception ex)
    {
        Progress.IsIndeterminate = false;

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
    if (_tenantResult == null)
    {
        MessageBox.Show(
            "Eseguire prima una scansione del tenant.",
            "CloudLens",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);

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
                _tenantResult);

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
        _tenantResult != null;

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

    Results.Visibility =
        Visibility.Visible;

    Score.Text =
        $"{result.Score}/100";

    ResourceCount.Text =
        result.Stats.Resources.ToString();

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

    CriticalCount.Text =
        result.Findings.Count(
            x => x.Severity == Severity.Critical)
        .ToString();

    HighCount.Text =
        result.Findings.Count(
            x => x.Severity == Severity.High)
        .ToString();

    MediumCount.Text =
        result.Findings.Count(
            x => x.Severity == Severity.Medium)
        .ToString();

    LowCount.Text =
        result.Findings.Count(
            x => x.Severity == Severity.Low)
        .ToString();

    RemediationCount.Text =
        result.Remediation.TotalActions.ToString();

    ReadyRemediationCount.Text =
        result.Remediation.ReadyActions.ToString();

    ReviewRemediationCount.Text =
        result.Remediation.ReviewRequiredActions.ToString();

    NotAutomatableCount.Text =
        result.Remediation.NotAutomatableActions.ToString();

    SubscriptionCount.Text =
        "1";

    EnrichmentCoverage.Text =
        $"{result.Stats.EnrichmentCoveragePercent:F1}%";

    MetricProfileCount.Text =
        result.Stats.MetricProfiles.ToString();

    FindingsGrid.ItemsSource =
        result.Findings;

    RemediationGrid.ItemsSource =
        result.Remediation.Actions;

    MetricsGrid.ItemsSource =
        result.MetricProfiles;

    PopulateCategoryScores(
        result.ScoresByCategory);
}


private void LoadTenantResult(
    TenantScanResult result)
{
    _tenantResult =
        result;

    Results.Visibility =
        Visibility.Visible;

    Score.Text =
        $"{result.OverallScore}/100";

    ResourceCount.Text =
        result.TotalResources.ToString();

    FindingCount.Text =
        result.AllFindings.Count.ToString();

    RemediationCount.Text =
        result.Subscriptions
            .Sum(
                x =>
                    x.Result.Remediation.TotalActions)
            .ToString();

    var saving =
        result.AllFindings.Sum(
            x =>
                x.MonthlySavingEur);

    Saving.Text =
        $"€ {saving:N2}";

    SavingYear.Text =
        $"€ {saving * 12:N2}";

    CriticalCount.Text =
        result.CriticalFindings.ToString();

    HighCount.Text =
        result.HighFindings.ToString();

    MediumCount.Text =
        result.MediumFindings.ToString();

    LowCount.Text =
        result.LowFindings.ToString();

    var allRemediationActions =
        result.Subscriptions
            .SelectMany(
                x =>
                    x.Result
                        .Remediation
                        .Actions)
            .ToList();

    ReadyRemediationCount.Text =
        allRemediationActions.Count(
            x =>
                x.Status ==
                RemediationStatus.Ready)
        .ToString();

    ReviewRemediationCount.Text =
        allRemediationActions.Count(
            x =>
                x.Status ==
                RemediationStatus.ReviewRequired)
        .ToString();

    NotAutomatableCount.Text =
        allRemediationActions.Count(
            x =>
                x.Status ==
                RemediationStatus.NotAutomatable)
        .ToString();

    SubscriptionCount.Text =
        result.Subscriptions.Count.ToString();

    EnrichmentCoverage.Text =
        $"{result.EnrichmentCoveragePercent:F1}%";

    MetricProfileCount.Text =
        result.TotalMetricProfiles.ToString();

    FindingsGrid.ItemsSource =
        result.AllFindings;

    RemediationGrid.ItemsSource =
        allRemediationActions;

    MetricsGrid.ItemsSource =
        result.AllMetricProfiles;

    PopulateCategoryScores(
        result.ScoresByCategory);

    ExportReportButton.IsEnabled =
        true;
}


private void PopulateCategoryScores(
    IReadOnlyDictionary<Category, int> scores)
{
    CategoryScoresPanel.Items.Clear();

    foreach (var category in
             Enum.GetValues<Category>())
    {
        var score =
            scores.TryGetValue(
                category,
                out var categoryScore)
                ? categoryScore
                : 100;

        var panel =
            new StackPanel
            {
                Margin =
                    new Thickness(
                        8)
            };

        var categoryText =
            new TextBlock
            {
                Text =
                    category.ToString(),

                Foreground =
                    new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(
                            102,
                            112,
                            133)),

                FontSize =
                    12
            };

        var scoreText =
            new TextBlock
            {
                Text =
                    $"{score}/100",

                FontSize =
                    24,

                FontWeight =
                    FontWeights.Bold
            };

        var progress =
            new ProgressBar
            {
                Minimum =
                    0,

                Maximum =
                    100,

                Value =
                    score,

                Height =
                    6,

                Margin =
                    new Thickness(
                        0,
                        8,
                        0,
                        0)
            };

        panel.Children.Add(
            categoryText);

        panel.Children.Add(
            scoreText);

        panel.Children.Add(
            progress);

        CategoryScoresPanel.Items.Add(
            panel);
    }
}
}
