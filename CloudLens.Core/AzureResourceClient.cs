using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureResourceClient
{
    private readonly HttpClient _http;
    private readonly string _token;

    private const string ArmBase =
        "https://management.azure.com";

    private const string ResourceGraphUrl =
        "https://management.azure.com/providers/Microsoft.ResourceGraph/resources" +
        "?api-version=2022-10-01";

    public AzureResourceClient(
        HttpClient http,
        string token)
    {
        _http =
            http ?? throw new ArgumentNullException(nameof(http));

        _token =
            string.IsNullOrWhiteSpace(token)
                ? throw new ArgumentException(
                    "Access token obbligatorio.",
                    nameof(token))
                : token;
    }

    // =========================================================
    // GENERIC ARM GET
    // =========================================================

    private async Task<JsonDocument> GetAsync(
        string url,
        CancellationToken cancellationToken)
    {
        using var request =
            new HttpRequestMessage(
                HttpMethod.Get,
                url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                _token);

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Azure Resource Manager ha restituito " +
                $"HTTP {(int)response.StatusCode}.\n\n" +
                body);
        }

        return JsonDocument.Parse(body);
    }

    // =========================================================
    // SUBSCRIPTIONS
    // =========================================================

    public async Task<List<AzureSubscription>>
        GetSubscriptionsAsync(
            CancellationToken cancellationToken = default)
    {
        var result =
            new List<AzureSubscription>();

        var url =
            $"{ArmBase}/subscriptions" +
            "?api-version=2022-12-01";

        while (!string.IsNullOrWhiteSpace(url))
        {
            using var json =
                await GetAsync(
                    url,
                    cancellationToken);

            if (json.RootElement.TryGetProperty(
                    "value",
                    out var values))
            {
                foreach (var item in
                         values.EnumerateArray())
                {
                    var id =
                        item.TryGetProperty(
                            "subscriptionId",
                            out var idElement)
                            ? idElement.GetString()
                            : null;

                    var name =
                        item.TryGetProperty(
                            "displayName",
                            out var nameElement)
                            ? nameElement.GetString()
                            : null;

                    var state =
                        item.TryGetProperty(
                            "state",
                            out var stateElement)
                            ? stateElement.GetString()
                            : null;

                    if (!string.IsNullOrWhiteSpace(id))
                    {
                        result.Add(
                            new AzureSubscription(
                                id,
                                name ?? id,
                                state ?? "Unknown"));
                    }
                }
            }

            url =
                json.RootElement.TryGetProperty(
                    "nextLink",
                    out var nextLink)
                    ? nextLink.GetString()
                    : null;
        }

        return result;
    }

    // =========================================================
    // RESOURCE GRAPH DISCOVERY
    // =========================================================

    public async Task<List<JsonElement>>
        GetResourcesAsync(
            string subscriptionId,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(subscriptionId))
        {
            throw new ArgumentException(
                "Subscription ID obbligatorio.",
                nameof(subscriptionId));
        }

        var resources =
            new List<JsonElement>();

        string? skipToken = null;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var query =
                new
                {
                    subscriptions =
                        new[]
                        {
                            subscriptionId
                        },

                    query =
                        """
                        Resources
                        | project
                            id,
                            name,
                            type,
                            resourceGroup,
                            location,
                            subscriptionId,
                            tags,
                            sku,
                            properties
                        | order by id asc
                        """,

                    options =
                        new
                        {
                            resultFormat = "objectArray"
                        },

                    skipToken
                };

            var json =
                await PostResourceGraphAsync(
                    query,
                    cancellationToken);

            if (!json.RootElement.TryGetProperty(
                    "data",
                    out var data))
            {
                break;
            }

            foreach (var item in
                     data.EnumerateArray())
            {
                resources.Add(
                    item.Clone());
            }

            skipToken = null;

            if (json.RootElement.TryGetProperty(
                    "$skipToken",
                    out var tokenElement))
            {
                skipToken =
                    tokenElement.GetString();
            }

            if (string.IsNullOrWhiteSpace(skipToken))
            {
                break;
            }
        }

        return resources;
    }

    // =========================================================
    // RESOURCE GRAPH POST
    // =========================================================

    private async Task<JsonDocument>
        PostResourceGraphAsync(
            object query,
            CancellationToken cancellationToken)
    {
        var jsonContent =
            JsonSerializer.Serialize(query);

        using var content =
            new StringContent(
                jsonContent,
                Encoding.UTF8,
                "application/json");

        using var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                ResourceGraphUrl);

        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                _token);

        request.Content =
            content;

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Azure Resource Graph ha restituito " +
                $"HTTP {(int)response.StatusCode}.\n\n" +
                body);
        }

        return JsonDocument.Parse(body);
    }

    // =========================================================
    // SINGLE RESOURCE
    // =========================================================

    public async Task<JsonElement?>
        GetResourceAsync(
            string resourceId,
            string apiVersion,
            CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            throw new ArgumentException(
                "Resource ID obbligatorio.",
                nameof(resourceId));
        }

        if (string.IsNullOrWhiteSpace(apiVersion))
        {
            throw new ArgumentException(
                "API version obbligatoria.",
                nameof(apiVersion));
        }

        var url =
            $"{ArmBase}{resourceId}" +
            "?api-version=" +
            $"{Uri.EscapeDataString(apiVersion)}";

        using var json =
            await GetAsync(
                url,
                cancellationToken);

        return json.RootElement.Clone();
    }
}

public sealed record AzureSubscription(
    string Id,
    string Name,
    string State);