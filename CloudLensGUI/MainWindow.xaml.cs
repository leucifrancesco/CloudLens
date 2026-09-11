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
    }

    private void LoadTenantResult(
        CloudLens.Core.TenantScanResult result)
    {
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

        ExportReportButton.IsEnabled =
            true;
    }
}