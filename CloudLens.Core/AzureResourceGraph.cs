namespace CloudLens.Core.Azure;

public sealed class AzureResourceGraph
{
    private readonly IReadOnlyDictionary<string, AzureResource> _resourcesById;

    public AzureResourceGraph(
        IReadOnlyList<AzureResource> resources)
    {
        _resourcesById =
            resources
                .Where(
                    x => !string.IsNullOrWhiteSpace(x.Id))
                .GroupBy(
                    x => NormalizeId(x.Id),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    x => x.Key,
                    x => x.First(),
                    StringComparer.OrdinalIgnoreCase);
    }

    public AzureResource? GetResource(
        string? resourceId)
    {
        if (string.IsNullOrWhiteSpace(resourceId))
        {
            return null;
        }

        return _resourcesById.TryGetValue(
            NormalizeId(resourceId),
            out var resource)
                ? resource
                : null;
    }

    public IReadOnlyList<AzureResource> GetResources(
        string resourceType)
    {
        return _resourcesById
            .Values
            .Where(
                x =>
                    string.Equals(
                        x.Type,
                        resourceType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public IReadOnlyList<AzureResource> GetRelatedResources(
        AzureResource resource,
        string relationshipType)
    {
        var result =
            new List<AzureResource>();

        foreach (var relationship in
                 resource.Relationships)
        {
            if (!string.Equals(
                    relationship.RelationshipType,
                    relationshipType,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var target =
                GetResource(
                    relationship.TargetResourceId);

            if (target != null)
            {
                result.Add(target);
            }
        }

        return result;
    }

    public AzureResource? GetRelatedResource(
        AzureResource resource,
        string relationshipType)
    {
        return GetRelatedResources(
                resource,
                relationshipType)
            .FirstOrDefault();
    }

    public IReadOnlyList<AzureResource> GetDependents(
        AzureResource resource,
        string relationshipType)
    {
        var normalizedId =
            NormalizeId(resource.Id);

        return _resourcesById
            .Values
            .Where(
                candidate =>
                    candidate.Relationships.Any(
                        relationship =>
                            string.Equals(
                                relationship.TargetResourceId
                                    .TrimEnd('/'),
                                normalizedId,
                                StringComparison.OrdinalIgnoreCase)
                            &&
                            string.Equals(
                                relationship.RelationshipType,
                                relationshipType,
                                StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    public bool HasRelationshipPath(
        AzureResource source,
        string targetType,
        params string[] relationshipTypes)
    {
        if (relationshipTypes.Length == 0)
        {
            return string.Equals(
                source.Type,
                targetType,
                StringComparison.OrdinalIgnoreCase);
        }

        var current =
            new List<AzureResource>
            {
                source
            };

        foreach (var relationshipType in
                 relationshipTypes)
        {
            var next =
                new List<AzureResource>();

            foreach (var resource in current)
            {
                next.AddRange(
                    GetRelatedResources(
                        resource,
                        relationshipType));
            }

            if (next.Count == 0)
            {
                return false;
            }

            current =
                next
                    .GroupBy(
                        x => NormalizeId(x.Id),
                        StringComparer.OrdinalIgnoreCase)
                    .Select(
                        x => x.First())
                    .ToList();
        }

        return current.Any(
            x =>
                string.Equals(
                    x.Type,
                    targetType,
                    StringComparison.OrdinalIgnoreCase));
    }

    public IReadOnlyList<AzureResource> FindResourcesAtPath(
        AzureResource source,
        string targetType,
        params string[] relationshipTypes)
    {
        if (relationshipTypes.Length == 0)
        {
            return string.Equals(
                    source.Type,
                    targetType,
                    StringComparison.OrdinalIgnoreCase)
                ? [source]
                : [];
        }

        var current =
            new List<AzureResource>
            {
                source
            };

        foreach (var relationshipType in
                 relationshipTypes)
        {
            var next =
                new List<AzureResource>();

            foreach (var resource in current)
            {
                next.AddRange(
                    GetRelatedResources(
                        resource,
                        relationshipType));
            }

            current =
                next
                    .GroupBy(
                        x => NormalizeId(x.Id),
                        StringComparer.OrdinalIgnoreCase)
                    .Select(
                        x => x.First())
                    .ToList();

            if (current.Count == 0)
            {
                break;
            }
        }

        return current
            .Where(
                x =>
                    string.Equals(
                        x.Type,
                        targetType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public IReadOnlyList<AzureResource> FindDependentsAtPath(
        AzureResource target,
        string targetType,
        params string[] relationshipTypes)
    {
        if (relationshipTypes.Length == 0)
        {
            return string.Equals(
                    target.Type,
                    targetType,
                    StringComparison.OrdinalIgnoreCase)
                ? [target]
                : [];
        }

        var current =
            new List<AzureResource>
            {
                target
            };

        foreach (var relationshipType in
                 relationshipTypes)
        {
            var next =
                new List<AzureResource>();

            foreach (var resource in current)
            {
                next.AddRange(
                    GetDependents(
                        resource,
                        relationshipType));
            }

            current =
                next
                    .GroupBy(
                        x => NormalizeId(x.Id),
                        StringComparer.OrdinalIgnoreCase)
                    .Select(
                        x => x.First())
                    .ToList();

            if (current.Count == 0)
            {
                break;
            }
        }

        return current
            .Where(
                x =>
                    string.Equals(
                        x.Type,
                        targetType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static string NormalizeId(
        string id)
    {
        return id.TrimEnd('/');
    }
}