using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureResourceEnrichment
{
    public bool Success { get; init; }

    public string? ApiVersion { get; init; }

    public DateTimeOffset CollectedAt { get; init; }

    public JsonElement? ArmResource { get; init; }

    public string? Error { get; init; }
}