namespace CloudLens.Core.Azure;

public sealed class AzureResourceGraph
{
    private readonly IReadOnlyDictionary<string, AzureResource> _resourcesById;

    public AzureResourceGraph(
        IReadOnlyList<AzureResource> resources)
    {
        if (resources == null)
            throw new ArgumentNullException(nameof(resources));

        _resourcesById =
            resources
                .Where(
                    resource =>
                        !string.IsNullOrWhiteSpace(resource.Id))
                .GroupBy(
                    resource =>
                        NormalizeId(resource.Id),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.First(),
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
        if (string.IsNullOrWhiteSpace(resourceType))
        {
            return [];
        }

        return _resourcesById
            .Values
            .Where(
                resource =>
                    string.Equals(
                        resource.Type,
                        resourceType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public IReadOnlyList<AzureResourceRelationship>
        GetRelationships(
            AzureResource resource)
    {
        if (resource == null)
            throw new ArgumentNullException(nameof(resource));

        return resource.Relationships
            .ToList();
    }

    public IReadOnlyList<AzureResourceRelationship>
        GetRelationships(
            AzureResource resource,
            string relationshipType)
    {
        if (resource == null)
            throw new ArgumentNullException(nameof(resource));

        if (string.IsNullOrWhiteSpace(relationshipType))
        {
            return [];
        }

        return resource.Relationships
            .Where(
                relationship =>
                    string.Equals(
                        relationship.RelationshipType,
                        relationshipType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public IReadOnlyList<AzureResourceRelationship>
        GetAllRelationships()
    {
        return _resourcesById
            .Values
            .SelectMany(
                resource => resource.Relationships)
            .ToList();
    }

    public bool HasRelationship(
        AzureResource source,
        string relationshipType,
        AzureResource target)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        if (target == null)
            throw new ArgumentNullException(nameof(target));

        if (string.IsNullOrWhiteSpace(relationshipType))
        {
            return false;
        }

        var normalizedTargetId =
            NormalizeId(target.Id);

        return source.Relationships.Any(
            relationship =>
                string.Equals(
                    relationship.RelationshipType,
                    relationshipType,
                    StringComparison.OrdinalIgnoreCase)
                &&
                string.Equals(
                    NormalizeId(
                        relationship.TargetResourceId),
                    normalizedTargetId,
                    StringComparison.OrdinalIgnoreCase));
    }

    public IReadOnlyList<AzureResource> GetRelatedResources(
        AzureResource resource,
        string relationshipType)
    {
        if (resource == null)
            throw new ArgumentNullException(nameof(resource));

        if (string.IsNullOrWhiteSpace(relationshipType))
        {
            return [];
        }

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

        return DistinctResources(result);
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
        if (resource == null)
            throw new ArgumentNullException(nameof(resource));

        if (string.IsNullOrWhiteSpace(relationshipType))
        {
            return [];
        }

        var normalizedId =
            NormalizeId(resource.Id);

        return _resourcesById
            .Values
            .Where(
                candidate =>
                    candidate.Relationships.Any(
                        relationship =>
                            string.Equals(
                                NormalizeId(
                                    relationship.TargetResourceId),
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
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        if (string.IsNullOrWhiteSpace(targetType))
        {
            return false;
        }

        if (relationshipTypes.Length == 0)
        {
            return string.Equals(
                source.Type,
                targetType,
                StringComparison.OrdinalIgnoreCase);
        }

        IReadOnlyList<AzureResource> current =
            new List<AzureResource>
            {
                source
            };

        foreach (var relationshipType in
                 relationshipTypes)
        {
            if (string.IsNullOrWhiteSpace(relationshipType))
            {
                return false;
            }

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
                DistinctResources(next);

            if (current.Count == 0)
            {
                return false;
            }
        }

        return current.Any(
            resource =>
                string.Equals(
                    resource.Type,
                    targetType,
                    StringComparison.OrdinalIgnoreCase));
    }

    public IReadOnlyList<AzureResource> FindResourcesAtPath(
        AzureResource source,
        string targetType,
        params string[] relationshipTypes)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        if (string.IsNullOrWhiteSpace(targetType))
        {
            return [];
        }

        if (relationshipTypes.Length == 0)
        {
            return string.Equals(
                    source.Type,
                    targetType,
                    StringComparison.OrdinalIgnoreCase)
                ? [source]
                : [];
        }

        IReadOnlyList<AzureResource> current =
            new List<AzureResource>
            {
                source
            };

        foreach (var relationshipType in
                 relationshipTypes)
        {
            if (string.IsNullOrWhiteSpace(relationshipType))
            {
                return [];
            }

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
                DistinctResources(next);

            if (current.Count == 0)
            {
                break;
            }
        }

        return current
            .Where(
                resource =>
                    string.Equals(
                        resource.Type,
                        targetType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public IReadOnlyList<AzureResource> FindDependentsAtPath(
        AzureResource target,
        string targetType,
        params string[] relationshipTypes)
    {
        if (target == null)
            throw new ArgumentNullException(nameof(target));

        if (string.IsNullOrWhiteSpace(targetType))
        {
            return [];
        }

        if (relationshipTypes.Length == 0)
        {
            return string.Equals(
                    target.Type,
                    targetType,
                    StringComparison.OrdinalIgnoreCase)
                ? [target]
                : [];
        }

        IReadOnlyList<AzureResource> current =
            new List<AzureResource>
            {
                target
            };

        foreach (var relationshipType in
                 relationshipTypes)
        {
            if (string.IsNullOrWhiteSpace(relationshipType))
            {
                return [];
            }

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
                DistinctResources(next);

            if (current.Count == 0)
            {
                break;
            }
        }

        return current
            .Where(
                resource =>
                    string.Equals(
                        resource.Type,
                        targetType,
                        StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static IReadOnlyList<AzureResource>
        DistinctResources(
            IEnumerable<AzureResource> resources)
    {
        return resources
            .Where(
                resource =>
                    resource != null &&
                    !string.IsNullOrWhiteSpace(resource.Id))
            .GroupBy(
                resource =>
                    NormalizeId(resource.Id),
                StringComparer.OrdinalIgnoreCase)
            .Select(
                group => group.First())
            .ToList();
    }

    private static string NormalizeId(
        string id)
    {
        return id
            .Trim()
            .TrimEnd('/');
    }
}