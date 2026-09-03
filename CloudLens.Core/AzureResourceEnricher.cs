using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureResourceEnricher
{
    private const string ArmBase =
        "https://management.azure.com";

    private const string ProviderApiVersion =
        "2021-04-01";

    private const int MaxConcurrentRequests = 6;

    /*
     * Fallback utilizzato solamente quando ARM non riesce
     * a fornire il metadata del provider/resource type.
     */
    private static readonly string[] DefaultApiVersions =
    [
        "2024-11-01",
        "2024-10-01",
        "2024-07-01",
        "2023-07-01",
        "2023-05-01",
        "2022-09-01",
        "2022-01-01",
        "2021-04-01",
        "2020-06-01"
    ];

    private readonly HttpClient _http;
    private readonly string _token;

    /*
     * Una Lazy<Task<T>> per provider garantisce che,
     * anche in presenza di richieste concorrenti, venga
     * eseguita una sola chiamata ARM per ottenere i metadata.
     */
    private readonly ConcurrentDictionary<
        string,
        Lazy<Task<ProviderMetadataResult>>>
        _providerMetadataCache =
            new(StringComparer.OrdinalIgnoreCase);

    public AzureResourceEnricher(
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
    // ENRICHMENT
    // =========================================================

    public async Task EnrichAsync(
        IReadOnlyList<AzureResource> resources,
        CancellationToken cancellationToken = default)
    {
        if (resources.Count == 0)
            return;

        using var semaphore =
            new SemaphoreSlim(
                MaxConcurrentRequests,
                MaxConcurrentRequests);

        var tasks =
            resources.Select(
                resource =>
                    EnrichResourceAsync(
                        resource,
                        semaphore,
                        cancellationToken));

        await Task.WhenAll(tasks);
    }

    // =========================================================
    // SINGLE RESOURCE
    // =========================================================

    private async Task EnrichResourceAsync(
        AzureResource resource,
        SemaphoreSlim semaphore,
        CancellationToken cancellationToken)
    {
        await semaphore.WaitAsync(
            cancellationToken);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var apiVersions =
                await GetApiVersionsAsync(
                    resource,
                    cancellationToken);

            string? lastError = null;

            foreach (var apiVersion in apiVersions)
            {
                cancellationToken.ThrowIfCancellationRequested();

                ArmGetResult result;

                try
                {
                    result =
                        await GetResourceAsync(
                            resource.Id,
                            apiVersion,
                            cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    lastError =
                        $"Errore durante la richiesta ARM " +
                        $"con API version {apiVersion}: " +
                        ex.Message;

                    continue;
                }

                if (result.Success &&
                    result.Resource.HasValue)
                {
                    resource.Enrichment =
                        new AzureResourceEnrichment
                        {
                            Success = true,
                            ApiVersion = apiVersion,
                            CollectedAt =
                                DateTimeOffset.UtcNow,
                            ArmResource =
                                result.Resource,
                            Error = null
                        };

                    return;
                }

                lastError =
                    BuildErrorMessage(
                        apiVersion,
                        result);
            }

            resource.Enrichment =
                new AzureResourceEnrichment
                {
                    Success = false,
                    CollectedAt =
                        DateTimeOffset.UtcNow,
                    Error =
                        lastError ??
                        "Nessuna API version compatibile " +
                        "ha restituito il resource ARM."
                };
        }
        finally
        {
            semaphore.Release();
        }
    }

    // =========================================================
    // API VERSION RESOLUTION
    // =========================================================

    private async Task<IReadOnlyList<string>>
        GetApiVersionsAsync(
            AzureResource resource,
            CancellationToken cancellationToken)
    {
        if (!TryParseResourceType(
                resource.Type,
                out var providerNamespace,
                out var resourceType))
        {
            return DefaultApiVersions;
        }

        var metadata =
            await GetProviderMetadataAsync(
                resource.SubscriptionId,
                providerNamespace,
                cancellationToken);

        if (!metadata.Success)
        {
            return DefaultApiVersions;
        }

        var matchingResourceType =
            metadata.ResourceTypes.FirstOrDefault(
                type =>
                    string.Equals(
                        type.Name,
                        resourceType,
                        StringComparison.OrdinalIgnoreCase));

        if (matchingResourceType == null)
        {
            return DefaultApiVersions;
        }

        var versions =
            new List<string>();

        /*
         * Prima proviamo la defaultApiVersion dichiarata
         * dal provider.
         */
        if (!string.IsNullOrWhiteSpace(
                matchingResourceType.DefaultApiVersion))
        {
            versions.Add(
                matchingResourceType.DefaultApiVersion);
        }

        /*
         * Poi proviamo le altre API version disponibili.
         */
        foreach (var version in
                 matchingResourceType.ApiVersions)
        {
            if (string.IsNullOrWhiteSpace(version))
                continue;

            if (!versions.Contains(
                    version,
                    StringComparer.OrdinalIgnoreCase))
            {
                versions.Add(version);
            }
        }

        return versions.Count > 0
            ? versions
            : DefaultApiVersions;
    }

    // =========================================================
    // PROVIDER METADATA
    // =========================================================

    private async Task<ProviderMetadataResult>
        GetProviderMetadataAsync(
            string subscriptionId,
            string providerNamespace,
            CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                subscriptionId))
        {
            return ProviderMetadataResult.Failed(
                "Subscription ID vuoto.");
        }

        if (string.IsNullOrWhiteSpace(
                providerNamespace))
        {
            return ProviderMetadataResult.Failed(
                "Provider namespace vuoto.");
        }

        var normalizedSubscriptionId =
            NormalizeSubscriptionId(
                subscriptionId);

        if (!Guid.TryParse(
                normalizedSubscriptionId,
                out _))
        {
            return ProviderMetadataResult.Failed(
                $"Subscription ID non valido: " +
                $"{subscriptionId}");
        }

        var lazyResult =
            _providerMetadataCache.GetOrAdd(
                providerNamespace,
                provider =>
                    new Lazy<Task<ProviderMetadataResult>>(
                        () =>
                            LoadProviderMetadataAsync(
                                normalizedSubscriptionId,
                                provider,
                                cancellationToken),
                        LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            return await lazyResult.Value;
        }
        catch (OperationCanceledException)
        {
            /*
             * Una cancellazione non deve lasciare nella cache
             * un task cancellato che impedisca future richieste.
             */
            _providerMetadataCache.TryRemove(
                new KeyValuePair<
                    string,
                    Lazy<Task<ProviderMetadataResult>>>(
                    providerNamespace,
                    lazyResult));

            throw;
        }
        catch (Exception ex)
        {
            /*
             * In caso di errore inatteso rimuoviamo l'elemento
             * dalla cache, permettendo un eventuale retry.
             */
            _providerMetadataCache.TryRemove(
                new KeyValuePair<
                    string,
                    Lazy<Task<ProviderMetadataResult>>>(
                    providerNamespace,
                    lazyResult));

            return ProviderMetadataResult.Failed(
                ex.Message);
        }
    }

    private async Task<ProviderMetadataResult>
        LoadProviderMetadataAsync(
            string subscriptionId,
            string providerNamespace,
            CancellationToken cancellationToken)
    {
        var url =
            $"{ArmBase}/subscriptions/" +
            $"{Uri.EscapeDataString(subscriptionId)}" +
            "/providers/" +
            $"{Uri.EscapeDataString(providerNamespace)}" +
            "?api-version=" +
            ProviderApiVersion;

        using var request =
            CreateRequest(
                HttpMethod.Get,
                url);

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return ProviderMetadataResult.Failed(
                $"HTTP {(int)response.StatusCode}: " +
                $"{ExtractErrorMessage(body)}");
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return ProviderMetadataResult.Failed(
                "Response provider metadata vuota.");
        }

        try
        {
            using var document =
                JsonDocument.Parse(body);

            if (!document.RootElement.TryGetProperty(
                    "resourceTypes",
                    out var resourceTypes) ||
                resourceTypes.ValueKind !=
                    JsonValueKind.Array)
            {
                return ProviderMetadataResult.Failed(
                    "Il provider non contiene resourceTypes.");
            }

            var result =
                new List<ProviderResourceTypeMetadata>();

            foreach (var resourceType
                     in resourceTypes.EnumerateArray())
            {
                var name =
                    GetString(
                        resourceType,
                        "resourceType");

                if (string.IsNullOrWhiteSpace(name))
                    continue;

                var defaultApiVersion =
                    GetString(
                        resourceType,
                        "defaultApiVersion");

                var apiVersions =
                    GetStringArray(
                        resourceType,
                        "apiVersions");

                result.Add(
                    new ProviderResourceTypeMetadata(
                        Name: name,
                        DefaultApiVersion:
                            defaultApiVersion,
                        ApiVersions:
                            apiVersions));
            }

            return new ProviderMetadataResult(
                Success: true,
                ResourceTypes: result,
                Error: null);
        }
        catch (JsonException ex)
        {
            return ProviderMetadataResult.Failed(
                $"JSON provider metadata non valido: " +
                $"{ex.Message}");
        }
    }

    // =========================================================
    // RESOURCE TYPE PARSING
    // =========================================================

    private static bool TryParseResourceType(
        string? type,
        out string providerNamespace,
        out string resourceType)
    {
        providerNamespace = string.Empty;
        resourceType = string.Empty;

        if (string.IsNullOrWhiteSpace(type))
            return false;

        var separatorIndex =
            type.IndexOf('/');

        if (separatorIndex <= 0 ||
            separatorIndex >= type.Length - 1)
        {
            return false;
        }

        providerNamespace =
            type[..separatorIndex];

        resourceType =
            type[(separatorIndex + 1)..];

        return
            !string.IsNullOrWhiteSpace(
                providerNamespace) &&
            !string.IsNullOrWhiteSpace(
                resourceType);
    }

    // =========================================================
    // ARM RESOURCE GET
    // =========================================================

    private async Task<ArmGetResult>
        GetResourceAsync(
            string resourceId,
            string apiVersion,
            CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            return new ArmGetResult(
                false,
                null,
                null,
                "Resource ID vuoto.");
        }

        var normalizedResourceId =
            NormalizeResourceId(
                resourceId);

        var url =
            $"{ArmBase}{normalizedResourceId}" +
            "?api-version=" +
            Uri.EscapeDataString(apiVersion);

        using var request =
            CreateRequest(
                HttpMethod.Get,
                url);

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return new ArmGetResult(
                false,
                null,
                (int)response.StatusCode,
                ExtractErrorMessage(body));
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            return new ArmGetResult(
                false,
                null,
                (int)response.StatusCode,
                "Response ARM vuota.");
        }

        try
        {
            using var json =
                JsonDocument.Parse(body);

            return new ArmGetResult(
                true,
                json.RootElement.Clone(),
                (int)response.StatusCode,
                null);
        }
        catch (JsonException ex)
        {
            return new ArmGetResult(
                false,
                null,
                (int)response.StatusCode,
                $"JSON ARM non valido: {ex.Message}");
        }
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
    // ERROR HANDLING
    // =========================================================

    private static string BuildErrorMessage(
        string apiVersion,
        ArmGetResult result)
    {
        var status =
            result.StatusCode.HasValue
                ? $"HTTP {result.StatusCode.Value}"
                : "HTTP sconosciuto";

        var error =
            string.IsNullOrWhiteSpace(
                result.Error)
                ? "Errore non specificato."
                : result.Error;

        return
            $"API version {apiVersion}: " +
            $"{status} - {error}";
    }

    private static string
        ExtractErrorMessage(
            string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "Response vuota.";

        try
        {
            using var document =
                JsonDocument.Parse(body);

            var root =
                document.RootElement;

            if (root.TryGetProperty(
                    "error",
                    out var error))
            {
                var code =
                    GetString(
                        error,
                        "code");

                var message =
                    GetString(
                        error,
                        "message");

                if (!string.IsNullOrWhiteSpace(code) &&
                    !string.IsNullOrWhiteSpace(message))
                {
                    return $"{code}: {message}";
                }

                if (!string.IsNullOrWhiteSpace(message))
                    return message;

                if (!string.IsNullOrWhiteSpace(code))
                    return code;
            }
        }
        catch (JsonException)
        {
            // La response potrebbe non essere JSON.
        }

        const int maxLength = 500;

        return body.Length <= maxLength
            ? body
            : body[..maxLength] + "...";
    }

    // =========================================================
    // NORMALIZATION
    // =========================================================

    private static string NormalizeResourceId(
        string resourceId)
    {
        var value =
            resourceId.Trim();

        if (!value.StartsWith(
                "/",
                StringComparison.Ordinal))
        {
            value =
                "/" + value;
        }

        return value.TrimEnd('/');
    }

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
    // JSON HELPERS
    // =========================================================

    private static string? GetString(
        JsonElement element,
        string propertyName)
    {
        if (!element.TryGetProperty(
                propertyName,
                out var value))
        {
            return null;
        }

        return value.ValueKind ==
               JsonValueKind.String
            ? value.GetString()
            : value.ToString();
    }

    private static IReadOnlyList<string>
        GetStringArray(
            JsonElement element,
            string propertyName)
    {
        var result =
            new List<string>();

        if (!element.TryGetProperty(
                propertyName,
                out var value) ||
            value.ValueKind !=
                JsonValueKind.Array)
        {
            return result;
        }

        foreach (var item
                 in value.EnumerateArray())
        {
            if (item.ValueKind !=
                JsonValueKind.String)
            {
                continue;
            }

            var text =
                item.GetString();

            if (!string.IsNullOrWhiteSpace(text))
            {
                result.Add(text);
            }
        }

        return result;
    }

    // =========================================================
    // METADATA MODELS
    // =========================================================

    private sealed record ProviderMetadataResult(
        bool Success,
        IReadOnlyList<ProviderResourceTypeMetadata>
            ResourceTypes,
        string? Error)
    {
        public static ProviderMetadataResult Failed(
            string error)
        {
            return new ProviderMetadataResult(
                Success: false,
                ResourceTypes: [],
                Error: error);
        }
    }

    private sealed record ProviderResourceTypeMetadata(
        string Name,
        string? DefaultApiVersion,
        IReadOnlyList<string> ApiVersions);

    private sealed record ArmGetResult(
        bool Success,
        JsonElement? Resource,
        int? StatusCode,
        string? Error);
}
