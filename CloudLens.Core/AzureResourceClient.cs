using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureResourceClient
{
    private const string ArmBase =
        "https://management.azure.com";

    private const string ResourceGraphEndpoint =
        "https://management.azure.com/providers/Microsoft.ResourceGraph/resources";

    private const string ResourceGraphApiVersion =
        "2024-04-01";

    private readonly HttpClient _http;
    private readonly string _token;

    public AzureResourceClient(
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
    // SUBSCRIPTIONS
    // =========================================================

    public async Task<List<AzureSubscription>>
        GetSubscriptionsAsync(
            CancellationToken cancellationToken = default)
    {
        var url =
            $"{ArmBase}/subscriptions" +
            "?api-version=2022-12-01";

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
            var body =
                await response.Content.ReadAsStringAsync(
                    cancellationToken);

            throw new HttpRequestException(
                $"Errore durante il recupero delle " +
                $"subscription Azure. " +
                $"HTTP {(int)response.StatusCode} " +
                $"{response.ReasonPhrase}. " +
                $"Response: {body}");
        }

        var json =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        using var document =
            JsonDocument.Parse(json);

        if (!document.RootElement.TryGetProperty(
                "value",
                out var values) ||
            values.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var subscriptions =
            new List<AzureSubscription>();

        foreach (var item in
                 values.EnumerateArray())
        {
            var id =
                GetString(
                    item,
                    "id");

            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var name =
                GetString(
                    item,
                    "displayName")
                ?? id;

            var state =
                GetString(
                    item,
                    "state");

            if (!string.Equals(
                    state,
                    "Enabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            subscriptions.Add(
                new AzureSubscription(
                    Id: id,
                    Name: name));
        }

        return subscriptions
            .OrderBy(
                x => x.Name,
                StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    // =========================================================
    // RESOURCE DISCOVERY
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

        // -----------------------------------------------------
        // Azure Resource Graph richiede il GUID puro.
        //
        // Azure ARM invece normalmente restituisce:
        //
        // /subscriptions/{GUID}
        //
        // Normalizziamo quindi il valore prima di inviarlo
        // a Resource Graph.
        // -----------------------------------------------------

        var normalizedSubscriptionId =
            NormalizeSubscriptionId(
                subscriptionId);

        if (!Guid.TryParse(
                normalizedSubscriptionId,
                out _))
        {
            throw new ArgumentException(
                $"Subscription ID non valido: " +
                $"{subscriptionId}",
                nameof(subscriptionId));
        }

        var resources =
            new List<JsonElement>();

        var skipToken =
            string.Empty;

        do
        {
            cancellationToken.ThrowIfCancellationRequested();

            var query =
                BuildResourceQuery(
                    normalizedSubscriptionId);

            var requestBody =
                new Dictionary<string, object?>
                {
                    ["subscriptions"] =
                        new[]
                        {
                            normalizedSubscriptionId
                        },

                    ["query"] =
                        query,

                    ["options"] =
                        new
                        {
                            resultFormat = "objectArray",

                            skipToken =
                                string.IsNullOrWhiteSpace(
                                    skipToken)
                                    ? null
                                    : skipToken
                        }
                };

            var jsonBody =
                JsonSerializer.Serialize(
                    requestBody);

            using var request =
                CreateRequest(
                    HttpMethod.Post,
                    $"{ResourceGraphEndpoint}" +
                    $"?api-version={ResourceGraphApiVersion}");

            request.Content =
                new StringContent(
                    jsonBody,
                    Encoding.UTF8,
                    "application/json");

            using var response =
                await _http.SendAsync(
                    request,
                    cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var body =
                    await response.Content.ReadAsStringAsync(
                        cancellationToken);

                throw new HttpRequestException(
                    $"Errore Azure Resource Graph. " +
                    $"HTTP {(int)response.StatusCode} " +
                    $"{response.ReasonPhrase}. " +
                    $"Response: {body}");
            }

            var responseBody =
                await response.Content.ReadAsStringAsync(
                    cancellationToken);

            using var document =
                JsonDocument.Parse(
                    responseBody);

            if (document.RootElement.TryGetProperty(
                    "data",
                    out var data) &&
                data.ValueKind ==
                    JsonValueKind.Array)
            {
                foreach (var resource in
                         data.EnumerateArray())
                {
                    resources.Add(
                        resource.Clone());
                }
            }

            skipToken =
                document.RootElement.TryGetProperty(
                    "$skipToken",
                    out var tokenElement)
                &&
                tokenElement.ValueKind ==
                    JsonValueKind.String
                    ? tokenElement.GetString() ?? ""
                    : "";

        }
        while (!string.IsNullOrWhiteSpace(skipToken));

        return resources;
    }

    // =========================================================
    // NORMALIZED RESOURCE DISCOVERY
    // =========================================================

    public async Task<List<AzureResource>>
        GetAzureResourcesAsync(
            string subscriptionId,
            CancellationToken cancellationToken = default)
    {
        var rawResources =
            await GetResourcesAsync(
                subscriptionId,
                cancellationToken);

        var resources =
            new List<AzureResource>();

        foreach (var raw in rawResources)
        {
            if (AzureResource.TryCreate(
                    raw,
                    out var resource) &&
                resource != null)
            {
                resources.Add(
                    resource);
            }
        }

        return resources;
    }

    // =========================================================
    // RESOURCE QUERY
    // =========================================================

    private static string BuildResourceQuery(
        string subscriptionId)
    {
        return """
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
            | order by type asc, name asc
            """;
    }

    // =========================================================
    // SUBSCRIPTION ID NORMALIZATION
    // =========================================================

    private static string NormalizeSubscriptionId(
        string subscriptionId)
    {
        var value =
            subscriptionId.Trim();

        const string prefix =
            "/subscriptions/";

        if (value.StartsWith(
                prefix,
                StringComparison.OrdinalIgnoreCase))
        {
            value =
                value[prefix.Length..];
        }

        return value.Trim('/');
    }

    // =========================================================
    // HTTP
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
    // JSON HELPERS
    // =========================================================

    private static string? GetString(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
                out var value))
        {
            return null;
        }

        return value.ValueKind ==
               JsonValueKind.String
            ? value.GetString()
            : value.ToString();
    }
}
