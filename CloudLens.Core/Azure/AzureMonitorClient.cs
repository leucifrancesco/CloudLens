using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using CloudLens.Core;

namespace CloudLens.Core.Azure;

public sealed class AzureMonitorClient
{
    private const string ArmBase =
        "https://management.azure.com";

    private const string MetricsApiVersion =
        "2018-01-01";

    private const string MetricDefinitionsApiVersion =
        "2018-01-01";

    private const int DefaultLookbackDays =
        90;

    private const int DefaultIntervalHours =
        1;

    private const int MaxConcurrentRequests =
        6;

    private readonly HttpClient _http;

    private readonly string _token;

    public AzureMonitorClient(
        HttpClient http,
        string token)
    {
        _http =
            http ??
            throw new ArgumentNullException(
                nameof(http));

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException(
                "Access token obbligatorio.",
                nameof(token));
        }

        _token = token;
    }

    public async Task<List<MetricProfile>> GetMetricsAsync(
        IReadOnlyList<JsonElement> resources,
        CancellationToken cancellationToken = default)
    {
        var collection =
            await GetMetricCollectionAsync(
                resources,
                cancellationToken);

        return collection.Profiles.ToList();
    }

    public async Task<MetricCollectionResult>
        GetMetricCollectionAsync(
            IReadOnlyList<JsonElement> resources,
            CancellationToken cancellationToken = default)
    {
        if (resources == null)
        {
            throw new ArgumentNullException(
                nameof(resources));
        }

        if (resources.Count == 0)
        {
            return new MetricCollectionResult();
        }

        var profiles =
            new ConcurrentBag<MetricProfile>();

        var coverage =
            new ConcurrentBag<MetricResourceCoverage>();

        using var semaphore =
            new SemaphoreSlim(
                MaxConcurrentRequests,
                MaxConcurrentRequests);

        var tasks =
            resources.Select(
                resource =>
                    CollectResourceMetricsAsync(
                        resource,
                        profiles,
                        coverage,
                        semaphore,
                        cancellationToken));

        await Task.WhenAll(tasks);

        return new MetricCollectionResult
        {
            Profiles =
                profiles
                    .OrderBy(x => x.ResourceType)
                    .ThenBy(x => x.ResourceName)
                    .ThenBy(x => x.MetricName)
                    .ToList(),

            Resources =
                coverage
                    .OrderBy(x => x.ResourceType)
                    .ThenBy(x => x.ResourceName)
                    .ToList()
        };
    }

    private async Task CollectResourceMetricsAsync(
        JsonElement resource,
        ConcurrentBag<MetricProfile> profiles,
        ConcurrentBag<MetricResourceCoverage> coverage,
        SemaphoreSlim semaphore,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var resourceId =
            GetString(
                resource,
                "id");

        var resourceName =
            GetString(
                resource,
                "name")
            ?? "Unknown";

        var resourceType =
            GetString(
                resource,
                "type")
            ?? "Unknown";

        if (string.IsNullOrWhiteSpace(resourceId))
        {
            return;
        }

        await semaphore.WaitAsync(
            cancellationToken);

        try
        {
            List<MetricDefinition> definitions;

            try
            {
                definitions =
                    await GetMetricDefinitionsAsync(
                        resourceId,
                        cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                coverage.Add(
                    new MetricResourceCoverage(
                        resourceId,
                        resourceName,
                        resourceType,
                        0,
                        0,
                        MetricCoverageStatus.Error,
                        ex.Message));

                return;
            }

            if (definitions.Count == 0)
            {
                coverage.Add(
                    new MetricResourceCoverage(
                        resourceId,
                        resourceName,
                        resourceType,
                        0,
                        0,
                        MetricCoverageStatus.Unsupported,
                        "Nessuna metric definition disponibile per la risorsa."));

                return;
            }

            var collectedMetrics = 0;
            var metricErrors = new List<string>();

            foreach (var definition in definitions)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var metricProfiles =
                        await GetMetricAsync(
                            resourceId,
                            resourceName,
                            resourceType,
                            definition,
                            DefaultLookbackDays,
                            cancellationToken);

                    foreach (var profile in metricProfiles)
                    {
                        profiles.Add(profile);
                        collectedMetrics++;
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    metricErrors.Add(
                        $"{definition.Name}: {ex.Message}");
                }
            }

            MetricCoverageStatus status;

            if (collectedMetrics > 0)
            {
                status =
                    MetricCoverageStatus.Collected;
            }
            else if (metricErrors.Count > 0)
            {
                status =
                    MetricCoverageStatus.Error;
            }
            else
            {
                status =
                    MetricCoverageStatus.NoData;
            }

            var error =
                metricErrors.Count == 0
                    ? null
                    : string.Join(
                        " | ",
                        metricErrors);

            coverage.Add(
                new MetricResourceCoverage(
                    resourceId,
                    resourceName,
                    resourceType,
                    definitions.Count,
                    collectedMetrics,
                    status,
                    error));
        }
        finally
        {
            semaphore.Release();
        }
    }

    private async Task<List<MetricDefinition>>
        GetMetricDefinitionsAsync(
            string resourceId,
            CancellationToken cancellationToken)
    {
        var url =
            $"{ArmBase}{resourceId}" +
            "/providers/Microsoft.Insights/metricDefinitions" +
            $"?api-version={MetricDefinitionsApiVersion}";

        using var request =
            CreateRequest(
                HttpMethod.Get,
                url);

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return [];
        }

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        using var json =
            JsonDocument.Parse(body);

        if (!json.RootElement.TryGetProperty(
                "value",
                out var values) ||
            values.ValueKind !=
            JsonValueKind.Array)
        {
            return [];
        }

        var result =
            new List<MetricDefinition>();

        foreach (var item in
                 values.EnumerateArray())
        {
            var name =
                GetString(
                    item,
                    "name",
                    "value");

            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var displayName =
                GetString(
                    item,
                    "name",
                    "localizedValue")
                ?? name;

            var unit =
                GetString(
                    item,
                    "unit");

            var namespaceName =
                GetString(
                    item,
                    "namespace");

            result.Add(
                new MetricDefinition(
                    name,
                    displayName,
                    unit,
                    namespaceName));
        }

        return result;
    }

    private async Task<List<MetricProfile>>
        GetMetricAsync(
            string resourceId,
            string resourceName,
            string resourceType,
            MetricDefinition definition,
            int lookbackDays,
            CancellationToken cancellationToken)
    {
        var endTime =
            DateTimeOffset.UtcNow;

        var startTime =
            endTime.AddDays(
                -lookbackDays);

        var url =
            $"{ArmBase}{resourceId}" +
            "/providers/Microsoft.Insights/metrics" +
            $"?api-version={MetricsApiVersion}" +
            $"&metricnames={Uri.EscapeDataString(definition.Name)}" +
            $"&timespan=" +
            $"{Uri.EscapeDataString(startTime.ToString("O"))}" +
            "/" +
            $"{Uri.EscapeDataString(endTime.ToString("O"))}" +
            $"&interval=PT{DefaultIntervalHours}H" +
            "&aggregation=Average,Minimum,Maximum";

        using var request =
            CreateRequest(
                HttpMethod.Get,
                url);

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return [];
        }

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        using var json =
            JsonDocument.Parse(body);

        if (!json.RootElement.TryGetProperty(
                "value",
                out var values) ||
            values.ValueKind !=
            JsonValueKind.Array)
        {
            return [];
        }

        var result =
            new List<MetricProfile>();

        foreach (var metric in
                 values.EnumerateArray())
        {
            var metricName =
                GetString(
                    metric,
                    "name",
                    "value")
                ?? definition.Name;

            var metricDisplayName =
                GetString(
                    metric,
                    "name",
                    "localizedValue")
                ?? definition.DisplayName;

            var unit =
                GetString(
                    metric,
                    "unit")
                ?? definition.Unit;

            var namespaceName =
                GetString(
                    metric,
                    "namespace")
                ?? definition.Namespace;

            if (!metric.TryGetProperty(
                    "timeseries",
                    out var timeseries) ||
                timeseries.ValueKind !=
                JsonValueKind.Array)
            {
                continue;
            }

            foreach (var series in
                     timeseries.EnumerateArray())
            {
                if (!series.TryGetProperty(
                        "data",
                        out var data) ||
                    data.ValueKind !=
                    JsonValueKind.Array)
                {
                    continue;
                }

                var averages =
                    new List<double>();

                var minimums =
                    new List<double>();

                var maximums =
                    new List<double>();

                foreach (var point in
                         data.EnumerateArray())
                {
                    AddMetricValue(
                        point,
                        "average",
                        averages);

                    AddMetricValue(
                        point,
                        "minimum",
                        minimums);

                    AddMetricValue(
                        point,
                        "maximum",
                        maximums);
                }

                if (averages.Count == 0 &&
                    minimums.Count == 0 &&
                    maximums.Count == 0)
                {
                    continue;
                }

                var allValues =
                    averages
                        .Concat(minimums)
                        .Concat(maximums)
                        .ToList();

                var average =
                    averages.Count > 0
                        ? averages.Average()
                        : allValues.Average();

                var minimum =
                    minimums.Count > 0
                        ? minimums.Min()
                        : allValues.Min();

                var maximum =
                    maximums.Count > 0
                        ? maximums.Max()
                        : allValues.Max();

                var sampleCount =
                    averages.Count > 0
                        ? averages.Count
                        : allValues.Count;

                result.Add(
                    new MetricProfile(
                        ResourceId:
                            resourceId,

                        ResourceName:
                            resourceName,

                        ResourceType:
                            resourceType,

                        MetricName:
                            metricName,

                        MetricDisplayName:
                            metricDisplayName,

                        Unit:
                            unit,

                        MetricNamespace:
                            namespaceName,

                        Average:
                            average,

                        Minimum:
                            minimum,

                        Maximum:
                            maximum,

                        SampleCount:
                            sampleCount,

                        LookbackDays:
                            lookbackDays));
            }
        }

        return result;
    }

    private HttpRequestMessage CreateRequest(
        HttpMethod method,
        string url)
    {
        var request =
            new HttpRequestMessage(
                method,
                url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                _token);

        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/json"));

        return request;
    }

    private static void AddMetricValue(
        JsonElement point,
        string property,
        List<double> values)
    {
        if (!point.TryGetProperty(
                property,
                out var value))
        {
            return;
        }

        if (value.ValueKind !=
            JsonValueKind.Number)
        {
            return;
        }

        if (value.TryGetDouble(
                out var number) &&
            !double.IsNaN(number) &&
            !double.IsInfinity(number))
        {
            values.Add(number);
        }
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        return element.TryGetProperty(
                property,
                out var value)
            && value.ValueKind ==
               JsonValueKind.String
                ? value.GetString()
                : null;
    }

    private static string? GetString(
        JsonElement element,
        string parentProperty,
        string childProperty)
    {
        if (!element.TryGetProperty(
                parentProperty,
                out var parent))
        {
            return null;
        }

        if (!parent.TryGetProperty(
                childProperty,
                out var child))
        {
            return null;
        }

        return child.ValueKind ==
               JsonValueKind.String
            ? child.GetString()
            : null;
    }

    private sealed record MetricDefinition(
        string Name,
        string DisplayName,
        string? Unit,
        string? Namespace);
}

public enum MetricCoverageStatus
{
    Collected,
    NoData,
    Unsupported,
    Error
}

public sealed record MetricResourceCoverage(
    string ResourceId,
    string ResourceName,
    string ResourceType,
    int AvailableMetricDefinitions,
    int CollectedMetricProfiles,
    MetricCoverageStatus Status,
    string? Error);

public sealed class MetricCollectionResult
{
    public IReadOnlyList<MetricProfile> Profiles { get; init; }
        = [];

    public IReadOnlyList<MetricResourceCoverage> Resources { get; init; }
        = [];
}