using System.Text.Json;

namespace CloudLens.Core.Azure;

public sealed class AzureResource
{
    public string Id { get; }

    public string Name { get; }

    public string Type { get; }

    public string ResourceGroup { get; }

    public string Location { get; }

    public string SubscriptionId { get; }

    public IReadOnlyDictionary<string, string> Tags { get; }

    public JsonElement? Sku { get; }

    public JsonElement? Properties { get; }

    public JsonElement Raw { get; }

    public AzureResourceEnrichment? Enrichment { get; set; }

    public List<AzureResourceRelationship> Relationships { get; } = [];
    public AzureResource(
        string id,
        string name,
        string type,
        string resourceGroup,
        string location,
        string subscriptionId,
        IReadOnlyDictionary<string, string>? tags,
        JsonElement? sku,
        JsonElement? properties,
        JsonElement raw)
    {
        Id = id;
        Name = name;
        Type = type;
        ResourceGroup = resourceGroup;
        Location = location;
        SubscriptionId = subscriptionId;

        Tags =
            tags ??
            new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);

        Sku = sku;
        Properties = properties;

        Raw = raw.Clone();
    }

    /// <summary>
    /// Permette al codice legacy degli analyzer di continuare
    /// a utilizzare TryGetProperty direttamente sulla risorsa.
    /// </summary>
    public bool TryGetProperty(
        string propertyName,
        out JsonElement value)
    {
        return Raw.TryGetProperty(
            propertyName,
            out value);
    }

    /// <summary>
    /// Accesso diretto al JSON originale.
    /// </summary>
    public JsonElement GetProperty(
        string propertyName)
    {
        return Raw.GetProperty(
            propertyName);
    }

    /// <summary>
    /// Conversione implicita temporanea per mantenere compatibilità
    /// con helper che utilizzano ancora JsonElement.
    /// </summary>
    public static implicit operator JsonElement(
        AzureResource resource)
    {
        return resource.Raw;
    }

    public override string ToString()
    {
        return $"{Type} | {Name} | {Id}";
    }

    public static bool TryCreate(
        JsonElement element,
        out AzureResource? resource)
    {
        resource = null;

        if (!TryGetString(
                element,
                "id",
                out var id) ||
            string.IsNullOrWhiteSpace(id))
        {
            return false;
        }

        TryGetString(
            element,
            "name",
            out var name);

        TryGetString(
            element,
            "type",
            out var type);

        TryGetString(
            element,
            "resourceGroup",
            out var resourceGroup);

        TryGetString(
            element,
            "location",
            out var location);

        TryGetString(
            element,
            "subscriptionId",
            out var subscriptionId);

        var tags =
            ReadTags(
                element);

        JsonElement? sku = null;

        if (element.TryGetProperty(
                "sku",
                out var skuElement))
        {
            sku =
                skuElement.Clone();
        }

        JsonElement? properties = null;

        if (element.TryGetProperty(
                "properties",
                out var propertiesElement))
        {
            properties =
                propertiesElement.Clone();
        }

        resource =
            new AzureResource(
                id!,
                name ?? "Unknown",
                type ?? "Unknown",
                resourceGroup ?? "",
                location ?? "",
                subscriptionId ?? "",
                tags,
                sku,
                properties,
                element);

        return true;
    }

    private static bool TryGetString(
        JsonElement element,
        string propertyName,
        out string? value)
    {
        value = null;

        if (!element.TryGetProperty(
                propertyName,
                out var property))
        {
            return false;
        }

        if (property.ValueKind !=
            JsonValueKind.String)
        {
            return false;
        }

        value =
            property.GetString();

        return true;
    }

    private static IReadOnlyDictionary<string, string>
        ReadTags(
            JsonElement element)
    {
        var result =
            new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);

        if (!element.TryGetProperty(
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
                    property.Value.GetString() ?? "";
            }
            else
            {
                result[property.Name] =
                    property.Value.ToString();
            }
        }

        return result;
    }
}