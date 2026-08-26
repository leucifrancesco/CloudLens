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
            http ?? throw new ArgumentNullException(
                nameof(http));

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException(
                "Access token obbligatorio.",
                nameof(token));
        }

        _token = token;
    }


    // =========================================================
    // PUBLIC API
    // =========================================================

    public async Task<List<MetricProfile>> GetMetricsAsync(
        IReadOnlyList<JsonElement> resources,
        CancellationToken cancellationToken = default)
    {
        var result =
            new ConcurrentBag<MetricProfile>();

        if (resources.Count == 0)
        {
            return [];
        }

        using var semaphore =
            new SemaphoreSlim(
                MaxConcurrentRequests,
                MaxConcurrentRequests);

        var tasks =
            resources.Select(
                resource =>
                    CollectResourceMetricsAsync(
                        resource,
                        result,
                        semaphore,
                        cancellationToken));

        await Task.WhenAll(tasks);

        return result
            .OrderBy(x => x.ResourceType)
            .ThenBy(x => x.ResourceName)
            .ThenBy(x => x.MetricName)
            .ToList();
    }


    // =========================================================
    // RESOURCE METRICS
    // =========================================================

    private async Task CollectResourceMetricsAsync(
        JsonElement resource,
        ConcurrentBag<MetricProfile> result,
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
                "type");

        if (string.IsNullOrWhiteSpace(resourceId) ||
            string.IsNullOrWhiteSpace(resourceType))
        {
            return;
        }

        try
        {
            await semaphore.WaitAsync(
                cancellationToken);

            try
            {
                var definitions =
                    await GetMetricDefinitionsAsync(
                        resourceId,
                        cancellationToken);

                if (definitions.Count == 0)
                {
                    return;
                }

                /*
                 * Azure Monitor può restituire molte metriche
                 * per una singola risorsa.
                 *
                 * Non chiediamo tutte le metriche in una sola
                 * query: costruiamo piccoli gruppi per evitare
                 * URL e risposte eccessivamente grandi.
                 */

                foreach (var definition in definitions)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        var profiles =
                            await GetMetricAsync(
                                resourceId,
                                resourceName,
                                resourceType,
                                definition,
                                DefaultLookbackDays,
                                cancellationToken);

                        foreach (var profile in profiles)
                        {
                            result.Add(profile);
                        }
                    }
                    catch
                    {
                        /*
                         * Una singola metrica non disponibile
                         * non deve interrompere la raccolta
                         * delle altre metriche della risorsa.
                         */
                    }
                }
            }
            finally
            {
                semaphore.Release();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            /*
             * Alcuni resource provider non espongono metriche
             * tramite l'endpoint standard.
             *
             * Questo è normale e non deve bloccare lo scan.
             */
        }
    }


    // =========================================================
    // METRIC DEFINITIONS
    // =========================================================

    private async Task<List<MetricDefinition>>
        GetMetricDefinitionsAsync(
            string resourceId,
            CancellationToken cancellationToken)
    {
        var url =
            $"{ArmBase}{resourceId}" +
            "/providers/Microsoft.Insights/metricDefinitions" +
            $"?api-version={MetricDefinitionsApiVersion}";

        try
        {
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
                    out var values))
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
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return [];
        }
    }


    // =========================================================
    // SINGLE METRIC
    // =========================================================

    private async Task<List<MetricProfile>> GetMetricAsync(
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
            endTime.AddDays(-lookbackDays);

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
                out var values))
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
                    out var timeseries))
            {
                continue;
            }

            foreach (var series in
                     timeseries.EnumerateArray())
            {
                if (!series.TryGetProperty(
                        "data",
                        out var data))
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


    // =========================================================
    // REQUEST CREATION
    // =========================================================

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


    // =========================================================
    // HELPERS
    // =========================================================

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


    // =========================================================
    // INTERNAL MODEL
    // =========================================================

    private sealed record MetricDefinition(
        string Name,
        string DisplayName,
        string? Unit,
        string? Namespace);
}