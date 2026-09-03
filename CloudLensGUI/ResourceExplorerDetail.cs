using CloudLens.Core.Azure;

namespace CloudLensGUI;

public sealed class ResourceExplorerDetail
{
    public AzureResource Resource { get; }

    public string Name =>
        Resource.Name;

    public string Type =>
        Resource.Type;

    public string ResourceGroup =>
        string.IsNullOrWhiteSpace(Resource.ResourceGroup)
            ? "—"
            : Resource.ResourceGroup;

    public string Location =>
        string.IsNullOrWhiteSpace(Resource.Location)
            ? "—"
            : Resource.Location;

    public string SubscriptionId =>
        string.IsNullOrWhiteSpace(Resource.SubscriptionId)
            ? "—"
            : Resource.SubscriptionId;

    public string Id =>
        Resource.Id;

    public string EnrichmentStatus =>
        Resource.Enrichment == null
            ? "Not processed"
            : Resource.Enrichment.Success
                ? "Success"
                : "Failed";

    public string EnrichmentApiVersion =>
        Resource.Enrichment?.ApiVersion
        ?? "—";

    public string TagsSummary =>
        Resource.Tags.Count == 0
            ? "Nessun tag"
            : string.Join(
                " | ",
                Resource.Tags.Select(
                    tag =>
                        $"{tag.Key}={tag.Value}"));

    public IReadOnlyList<ResourceExplorerRelationshipItem>
        Relationships { get; }

    public ResourceExplorerDetail(
        AzureResource resource,
        AzureResourceGraph graph)
    {
        Resource =
            resource ??
            throw new ArgumentNullException(nameof(resource));

        if (graph == null)
            throw new ArgumentNullException(nameof(graph));

        Relationships =
            graph
                .GetRelationships(resource)
                .Select(
                    relationship =>
                    {
                        var target =
                            graph.GetResource(
                                relationship.TargetResourceId);

                        return new ResourceExplorerRelationshipItem(
                            relationship,
                            target);
                    })
                .OrderBy(
                    relationship =>
                        relationship.RelationshipType)
                .ThenBy(
                    relationship =>
                        relationship.TargetName)
                .ToList();
    }
}


public sealed class ResourceExplorerRelationshipItem
{
    public string RelationshipType { get; }

    public string TargetName { get; }

    public string TargetType { get; }

    public string TargetResourceId { get; }

    public AzureResource? TargetResource { get; }

    public ResourceExplorerRelationshipItem(
        AzureResourceRelationship relationship,
        AzureResource? targetResource)
    {
        if (relationship == null)
            throw new ArgumentNullException(nameof(relationship));

        RelationshipType =
            relationship.RelationshipType;

        TargetResource =
            targetResource;

        TargetName =
            targetResource?.Name
            ?? relationship.TargetResourceId;

        TargetType =
            targetResource?.Type
            ?? "Unknown";

        TargetResourceId =
            relationship.TargetResourceId;
    }
}