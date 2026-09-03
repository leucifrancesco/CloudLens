using CloudLens.Core.Azure;

namespace CloudLensGUI;

public sealed class ResourceExplorerItem
{
    public AzureResource Resource { get; }

    public string Name =>
        Resource.Name;

    public string Type =>
        Resource.Type;

    public string ResourceGroup =>
        Resource.ResourceGroup;

    public string Location =>
        Resource.Location;

    public string SubscriptionId =>
        Resource.SubscriptionId;

    public string Id =>
        Resource.Id;

    public int RelationshipCount =>
        Resource.Relationships.Count;

    public int TagCount =>
        Resource.Tags.Count;

    public bool IsEnriched =>
        Resource.Enrichment?.Success == true;

    public string EnrichmentStatus =>
        Resource.Enrichment == null
            ? "Not processed"
            : Resource.Enrichment.Success
                ? "Success"
                : "Failed";

    public ResourceExplorerItem(
        AzureResource resource)
    {
        Resource =
            resource ??
            throw new ArgumentNullException(nameof(resource));
    }
}