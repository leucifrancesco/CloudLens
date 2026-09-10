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
        var subscriptions =
            new List<AzureSubscription>();

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

        var content =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Errore Azure Subscription API. " +
                $"HTTP {(int)response.StatusCode} " +
                $"{response.StatusCode}. " +
                $"Response: {content}");
        }

        using var document =
            JsonDocument.Parse(content);

        if (!document.RootElement.TryGetProperty(
                "value",
                out var values) ||
            values.ValueKind != JsonValueKind.Array)
        {
            return subscriptions;
        }

        foreach (var item in values.EnumerateArray())
        {
            var id =
                GetString(
                    item,
                    "subscriptionId");

            var name =
                GetString(
                    item,
                    "displayName");

            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            subscriptions.Add(
                new AzureSubscription(
                    id,
                    name ?? id));
        }

        return subscriptions;
    }

    // =========================================================
    // RESOURCE DISCOVERY
    // =========================================================

    public async Task<List<AzureResource>>
        GetAzureResourcesAsync(
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
            new List<AzureResource>();

        string? skipToken = null;

        do
        {
            var query =
                BuildResourceQuery();

            var payload =
                new Dictionary<string, object?>
                {
                    ["subscriptions"] =
                        new[]
                        {
                            subscriptionId
                        },

                    ["query"] =
                        query,

                    ["options"] =
                        new Dictionary<string, object?>
                        {
                            ["resultFormat"] =
                                "objectArray"
                        }
                };

            if (!string.IsNullOrWhiteSpace(
                    skipToken))
            {
                payload["options"] =
                    new Dictionary<string, object?>
                    {
                        ["resultFormat"] =
                            "objectArray",

                        ["$skipToken"] =
                            skipToken
                    };
            }

            var json =
                JsonSerializer.Serialize(
                    payload);

            using var request =
                CreateRequest(
                    HttpMethod.Post,
                    $"{ResourceGraphEndpoint}" +
                    $"?api-version={ResourceGraphApiVersion}");

            request.Content =
                new StringContent(
                    json,
                    Encoding.UTF8,
                    "application/json");

            using var response =
                await _http.SendAsync(
                    request,
                    cancellationToken);

            var content =
                await response.Content.ReadAsStringAsync(
                    cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(
                    $"Errore Azure Resource Graph. " +
                    $"HTTP {(int)response.StatusCode} " +
                    $"{response.StatusCode}.");

                Console.WriteLine(
                    $"Response: {content}");

                throw new HttpRequestException(
                    $"Azure Resource Graph ha restituito " +
                    $"HTTP {(int)response.StatusCode}.");
            }

            using var document =
                JsonDocument.Parse(content);

            if (document.RootElement.TryGetProperty(
                    "data",
                    out var data) &&
                data.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in
                         data.EnumerateArray())
                {
                    var resource =
                        CreateResource(
                            item);

                    if (resource != null)
                    {
                        resources.Add(
                            resource);
                    }
                }
            }

            skipToken =
                document.RootElement.TryGetProperty(
                    "$skipToken",
                    out var tokenElement)
                    ? tokenElement.GetString()
                    : null;

        } while (!string.IsNullOrWhiteSpace(
            skipToken));

        return resources;
    }

    // =========================================================
    // RESOURCE GRAPH QUERY
    // =========================================================

    private static string BuildResourceQuery()
    {
        return """
Resources
| extend resourceIdLower = tolower(id)
| join kind=leftouter (
    RecoveryServicesResources
    | where type =~ 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems'
    | where properties.backupManagementType =~ 'AzureIaasVM'
    | where isnotempty(properties.sourceResourceId)
    | project
        backupResourceId =
            tolower(tostring(properties.sourceResourceId)),
        backupProtected = true
) on $left.resourceIdLower == $right.backupResourceId
| extend
    backupProtectedValue =
        coalesce(backupProtected, false)
| project
    id,
    name,
    type,
    resourceGroup,
    location,
    subscriptionId,
    tags,
    sku,
    properties,
    backupProtectedValue
| order by type asc, name asc
""";
    }

    // =========================================================
    // RESOURCE CREATION
    // =========================================================

    private static AzureResource? CreateResource(
        JsonElement item)
    {
        var id =
            GetString(
                item,
                "id");

        var name =
            GetString(
                item,
                "name");

        var type =
            GetString(
                item,
                "type");

        if (string.IsNullOrWhiteSpace(id) ||
            string.IsNullOrWhiteSpace(name) ||
            string.IsNullOrWhiteSpace(type))
        {
            return null;
        }

        var resourceGroup =
            GetString(
                item,
                "resourceGroup") ??
            string.Empty;

        var location =
            GetString(
                item,
                "location") ??
            string.Empty;

        var subscriptionId =
            GetString(
                item,
                "subscriptionId") ??
            NormalizeSubscriptionId(
                id);

        var tags =
            ReadTags(
                item);

        JsonElement? sku =
            null;

        if (item.TryGetProperty(
                "sku",
                out var skuElement) &&
            skuElement.ValueKind ==
                JsonValueKind.Object)
        {
            sku =
                skuElement.Clone();
        }

        var properties =
            BuildProperties(
                item);

        return new AzureResource(
            id,
            name,
            type,
            resourceGroup,
            location,
            subscriptionId,
            tags,
            sku,
            properties,
            item.Clone());
    }

    private static JsonElement?
        BuildProperties(
            JsonElement item)
    {
        JsonElement properties;

        if (item.TryGetProperty(
                "properties",
                out var propertiesElement) &&
            propertiesElement.ValueKind ==
                JsonValueKind.Object)
        {
            properties =
                propertiesElement.Clone();
        }
        else
        {
            using var emptyDocument =
                JsonDocument.Parse("{}");

            properties =
                emptyDocument.RootElement.Clone();
        }

        var backupProtected =
            false;

        if (item.TryGetProperty(
                "backupProtectedValue",
                out var backupElement))
        {
            backupProtected =
                backupElement.ValueKind ==
                JsonValueKind.True;
        }

        using var stream =
            new MemoryStream();

        using (
            var writer =
                new Utf8JsonWriter(
                    stream))
        {
            writer.WriteStartObject();

            foreach (var property in
                     properties.EnumerateObject())
            {
                property.WriteTo(
                    writer);
            }

            writer.WriteBoolean(
                "cloudLensBackupProtected",
                backupProtected);

            writer.WriteEndObject();
        }

        using var document =
            JsonDocument.Parse(
                stream.ToArray());

        return document.RootElement.Clone();
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
    // HELPERS
    // =========================================================

    private static string NormalizeSubscriptionId(
        string resourceId)
    {
        var parts =
            resourceId.Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries);

        for (var index = 0;
             index < parts.Length - 1;
             index++)
        {
            if (string.Equals(
                    parts[index],
                    "subscriptions",
                    StringComparison.OrdinalIgnoreCase))
            {
                return parts[index + 1];
            }
        }

        return string.Empty;
    }

    private static string? GetString(
        JsonElement element,
        string property)
    {
        if (!element.TryGetProperty(
                property,
                out var value) ||
            value.ValueKind !=
                JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static IReadOnlyDictionary<string, string>
        ReadTags(
            JsonElement item)
    {
        var result =
            new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);

        if (!item.TryGetProperty(
                "tags",
                out var tags) ||
            tags.ValueKind !=
                JsonValueKind.Object)
        {
            return result;
        }

        foreach (var property in
                 tags.EnumerateObject())
        {
            if (property.Value.ValueKind ==
                JsonValueKind.String)
            {
                result[property.Name] =
                    property.Value.GetString() ??
                    string.Empty;
            }
            else
            {
                result[property.Name] =
                    property.Value.GetRawText();
            }
        }

        return result;
    }
}