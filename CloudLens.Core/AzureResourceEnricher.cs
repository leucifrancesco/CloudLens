using System.Net.Http.Headers;
using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureResourceEnricher
{
    private const string ArmBase =
        "https://management.azure.com";

    private const int MaxConcurrentRequests = 6;

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

    public async Task EnrichAsync(
        IReadOnlyList<AzureResource> resources,
        CancellationToken cancellationToken = default)
    {
        if (resources.Count == 0)
        {
            return;
        }

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
                GetApiVersions(resource);

            foreach (var apiVersion in apiVersions)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var result =
                        await GetResourceAsync(
                            resource.Id,
                            apiVersion,
                            cancellationToken);

                    if (result.Success)
                    {
                        resource.Enrichment =
                            new AzureResourceEnrichment
                            {
                                Success = true,
                                ApiVersion = apiVersion,
                                CollectedAt =
                                    DateTimeOffset.UtcNow,
                                ArmResource =
                                    result.Resource
                            };

                        return;
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                }
            }

            resource.Enrichment =
                new AzureResourceEnrichment
                {
                    Success = false,
                    CollectedAt =
                        DateTimeOffset.UtcNow,
                    Error =
                        "Nessuna API version compatibile " +
                        "ha restituito il resource ARM."
                };
        }
        finally
        {
            semaphore.Release();
        }
    }

    private static IReadOnlyList<string>
        GetApiVersions(
            AzureResource resource)
    {
        return DefaultApiVersions;
    }

    private async Task<ArmGetResult>
        GetResourceAsync(
            string resourceId,
            string apiVersion,
            CancellationToken cancellationToken)
    {
        var url =
            $"{ArmBase}{resourceId}" +
            "?api-version=" +
            Uri.EscapeDataString(apiVersion);

        using var request =
            new HttpRequestMessage(
                HttpMethod.Get,
                url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                _token);

        request.Headers.Accept.Add(
            new MediaTypeWithQualityHeaderValue(
                "application/json"));

        using var response =
            await _http.SendAsync(
                request,
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return new ArmGetResult(
                false,
                null);
        }

        var body =
            await response.Content.ReadAsStringAsync(
                cancellationToken);

        if (string.IsNullOrWhiteSpace(body))
        {
            return new ArmGetResult(
                false,
                null);
        }

        using var json =
            JsonDocument.Parse(body);

        return new ArmGetResult(
            true,
            json.RootElement.Clone());
    }

    private sealed record ArmGetResult(
        bool Success,
        JsonElement? Resource);
}