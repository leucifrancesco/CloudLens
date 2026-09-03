using System.Net.Http;
using System.Windows;
using System.Windows.Input;
using CloudLens.Core;
using CloudLens.Core.Azure;

namespace CloudLensGUI;

public partial class MainWindow : Window
{
    private readonly HttpClient _http = new();

    private AzureCollector? _collector;

    private List<AzureSubscription> _subscriptions = [];

    private ScanResult? _result;

    private List<ResourceExplorerItem> _resourceExplorerItems = [];

    private ResourceExplorerDetail? _selectedResourceDetail;

    private string? _tenantId;

    private string? _accessToken;

    private bool _authenticated;


    public MainWindow()
    {
        InitializeComponent();

        Subscription.Items.Add(
            "Accedere prima con Microsoft");

        Subscription.SelectedIndex = 0;

        ResourceDetailPanel.Visibility =
            Visibility.Collapsed;
    }


    // =========================================================
    // DEMO
    // =========================================================

    private void Demo_Click(
        object sender,
        RoutedEventArgs e)
    {
        LoadResult(
            DemoAnalyzer.CreateDemo());
    }


    // =========================================================
    // MICROSOFT LOGIN
    // =========================================================

    private async void Login_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(Tenant.Text))
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


            // -------------------------------------------------
            // LOGIN + SUBSCRIPTION DISCOVERY
            // -------------------------------------------------

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


            // -------------------------------------------------
            // SUBSCRIPTION LIST
            // -------------------------------------------------

            Subscription.Items.Clear();

            foreach (var subscription in _subscriptions)
            {
                Subscription.Items.Add(
                    $"{subscription.Name} ({subscription.Id})");
            }


            // -------------------------------------------------
            // NESSUNA SUBSCRIPTION
            // -------------------------------------------------

            if (_subscriptions.Count == 0)
            {
                _authenticated = false;
                _accessToken = null;

                Progress.Value = 100;

                StatusText.Text =
                    "Autenticazione riuscita, ma nessuna subscription è accessibile.";

                MessageBox.Show(
                    "L'autenticazione Microsoft è riuscita, ma il tuo account non vede alcuna subscription Azure.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }


            // -------------------------------------------------
            // LOGIN COMPLETATO
            // -------------------------------------------------

            Subscription.SelectedIndex = 0;

            _authenticated = true;

            Progress.Value = 100;

            StatusText.Text =
                $"Autenticazione riuscita. {_subscriptions.Count} subscription disponibili.";
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


    // =========================================================
    // ASSESSMENT
    // =========================================================

    private async void Run_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            if (!_authenticated ||
                string.IsNullOrWhiteSpace(_accessToken))
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


            var index =
                Subscription.SelectedIndex;

            if (index < 0 ||
                index >= _subscriptions.Count)
            {
                MessageBox.Show(
                    "Selezionare una subscription.",
                    "CloudLens",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }


            SetBusy(true);

            StatusPanel.Visibility =
                Visibility.Visible;

            StatusText.Text =
                "Esecuzione assessment Azure...";

            Progress.IsIndeterminate =
                true;


            _collector ??=
                new AzureCollector(_http);


            var selected =
                _subscriptions[index];


            // -------------------------------------------------
            // ASSESSMENT CON TOKEN ESISTENTE
            // -------------------------------------------------

            var result =
                await _collector.ScanInteractiveAsync(
                    _accessToken,
                    selected);


            Progress.IsIndeterminate =
                false;

            Progress.Value =
                100;

            StatusText.Text =
                "Assessment completato.";

            LoadResult(result);
        }
        catch (Exception ex)
        {
            Progress.IsIndeterminate =
                false;

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


    // =========================================================
    // RESOURCE EXPLORER
    // =========================================================

    private void ResourcesGrid_SelectionChanged(
        object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_result == null)
        {
            ClearResourceDetail();
            return;
        }

        if (ResourcesGrid.SelectedItem
            is not ResourceExplorerItem item)
        {
            ClearResourceDetail();
            return;
        }

        var graph =
            new AzureResourceGraph(
                _result.Resources);

        _selectedResourceDetail =
            new ResourceExplorerDetail(
                item.Resource,
                graph);

        ResourceDetailPanel.Visibility =
            Visibility.Visible;

        DetailName.Text =
            _selectedResourceDetail.Name;

        DetailType.Text =
            _selectedResourceDetail.Type;

        DetailResourceGroup.Text =
            _selectedResourceDetail.ResourceGroup;

        DetailLocation.Text =
            _selectedResourceDetail.Location;

        DetailSubscriptionId.Text =
            _selectedResourceDetail.SubscriptionId;

        DetailId.Text =
            _selectedResourceDetail.Id;

        DetailEnrichmentStatus.Text =
            _selectedResourceDetail.EnrichmentStatus;

        DetailEnrichmentApiVersion.Text =
            _selectedResourceDetail.EnrichmentApiVersion;

        DetailTags.Text =
            _selectedResourceDetail.TagsSummary;

        RelationshipsGrid.ItemsSource =
            _selectedResourceDetail.Relationships;
    }


    private void ClearResourceDetail()
    {
        _selectedResourceDetail = null;

        ResourceDetailPanel.Visibility =
            Visibility.Collapsed;

        RelationshipsGrid.ItemsSource =
            null;
    }


    // =========================================================
    // UI STATE
    // =========================================================

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

        Tenant.IsEnabled =
            !busy;
    }


    // =========================================================
    // RESULTS
    // =========================================================

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
                x => x.MonthlySavingEur);

        Saving.Text =
            $"€ {saving:N2}";

        SavingYear.Text =
            $"€ {saving * 12:N2}";

        FindingsGrid.ItemsSource =
            result.Findings;

        MetricsGrid.ItemsSource =
            result.MetricProfiles;


        // =====================================================
        // RESOURCE EXPLORER
        // =====================================================

        _resourceExplorerItems =
            result.Resources
                .Where(
                    resource =>
                        resource != null)
                .Select(
                    resource =>
                        new ResourceExplorerItem(
                            resource))
                .OrderBy(
                    item => item.Type)
                .ThenBy(
                    item => item.Name)
                .ToList();

        ResourcesGrid.ItemsSource =
            _resourceExplorerItems;

        ResourcesGrid.SelectedItem =
            null;

        ClearResourceDetail();


        // =====================================================
        // ENRICHMENT DIAGNOSTICS
        // =====================================================

        var enrichment =
            result.Enrichment;

        var message =
            $"Risorse totali: {enrichment.TotalResources}\n" +
            $"Enrichment riusciti: {enrichment.Successful}\n" +
            $"Enrichment falliti: {enrichment.Failed}\n" +
            $"Non processate: {enrichment.NotProcessed}\n" +
            $"Success rate: {enrichment.SuccessRate:F1}%\n";


        // -----------------------------------------------------
        // API VERSIONS
        // -----------------------------------------------------

        if (enrichment.ApiVersions.Count > 0)
        {
            message +=
                "\nAPI versions:\n";

            foreach (var version in
                     enrichment.ApiVersions
                         .OrderByDescending(
                             item => item.Value))
            {
                message +=
                    $"  {version.Key}: " +
                    $"{version.Value}\n";
            }
        }


        // -----------------------------------------------------
        // ERRORS
        // -----------------------------------------------------

        if (enrichment.Errors.Count > 0)
        {
            message +=
                "\nErrori enrichment:\n";

            foreach (var error in
                     enrichment.Errors)
            {
                message +=
                    $"\n{error.Key}\n" +
                    $"{error.Value}\n";
            }
        }


        MessageBox.Show(
            message,
            "CloudLens — Enrichment diagnostics",
            MessageBoxButton.OK,
            enrichment.Failed > 0
                ? MessageBoxImage.Warning
                : MessageBoxImage.Information);
    }
}