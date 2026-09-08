namespace CloudLens.Core.Azure;

public sealed class AzureResourceGraph
{
private readonly IReadOnlyDictionary<string, AzureResource>
_resourcesById;

public AzureResourceGraph(
    IReadOnlyList<AzureResource> resources)
{
    if (resources == null)
    {
        throw new ArgumentNullException(
            nameof(resources));
    }

    _resourcesById =
        resources
            .Where(
                resource =>
                    !string.IsNullOrWhiteSpace(
                        resource.Id))
            .GroupBy(
                resource =>
                    NormalizeId(resource.Id),
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.First(),
                StringComparer.OrdinalIgnoreCase);
}

// =========================================================
// RESOURCE LOOKUP
// =========================================================

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
        .OrderBy(
            resource =>
                resource.Name,
            StringComparer.OrdinalIgnoreCase)
        .ToList();
}

// =========================================================
// DIRECT RELATIONSHIPS
// =========================================================

public IReadOnlyList<AzureResource> GetRelatedResources(
    AzureResource resource,
    string relationshipType)
{
    if (resource == null)
    {
        throw new ArgumentNullException(
            nameof(resource));
    }

    if (string.IsNullOrWhiteSpace(
            relationshipType))
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
        .Select(
            relationship =>
                GetResource(
                    relationship.TargetResourceId))
        .Where(
            target =>
                target != null)
        .Cast<AzureResource>()
        .GroupBy(
            target =>
                NormalizeId(target.Id),
            StringComparer.OrdinalIgnoreCase)
        .Select(
            group =>
                group.First())
        .OrderBy(
            resource =>
                resource.Name,
            StringComparer.OrdinalIgnoreCase)
        .ToList();
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

// =========================================================
// DEPENDENTS
// =========================================================

public IReadOnlyList<AzureResource> GetDependents(
    AzureResource resource,
    string relationshipType)
{
    if (resource == null)
    {
        throw new ArgumentNullException(
            nameof(resource));
    }

    if (string.IsNullOrWhiteSpace(
            relationshipType))
    {
        return [];
    }

    var targetId =
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
                            targetId,
                            StringComparison.OrdinalIgnoreCase)
                        &&
                        string.Equals(
                            relationship.RelationshipType,
                            relationshipType,
                            StringComparison.OrdinalIgnoreCase)))
        .GroupBy(
            candidate =>
                NormalizeId(candidate.Id),
            StringComparer.OrdinalIgnoreCase)
        .Select(
            group =>
                group.First())
        .OrderBy(
            candidate =>
                candidate.Name,
            StringComparer.OrdinalIgnoreCase)
        .ToList();
}

// =========================================================
// FORWARD PATH
// =========================================================

public bool HasRelationshipPath(
    AzureResource source,
    string targetType,
    params string[] relationshipTypes)
{
    return FindResourcesAtPath(
            source,
            targetType,
            relationshipTypes)
        .Count > 0;
}

public IReadOnlyList<AzureResource> FindResourcesAtPath(
    AzureResource source,
    string targetType,
    params string[] relationshipTypes)
{
    if (source == null)
    {
        throw new ArgumentNullException(
            nameof(source));
    }

    if (string.IsNullOrWhiteSpace(targetType))
    {
        return [];
    }

    if (relationshipTypes == null ||
        relationshipTypes.Length == 0)
    {
        return TypeEquals(
                source,
                targetType)
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
        if (string.IsNullOrWhiteSpace(
                relationshipType))
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
            DistinctResources(
                next);

        if (current.Count == 0)
        {
            return [];
        }
    }

    return current
        .Where(
            resource =>
                TypeEquals(
                    resource,
                    targetType))
        .OrderBy(
            resource =>
                resource.Name,
            StringComparer.OrdinalIgnoreCase)
        .ToList();
}

// =========================================================
// REVERSE PATH
// =========================================================

public IReadOnlyList<AzureResource> FindDependentsAtPath(
    AzureResource target,
    string targetType,
    params string[] relationshipTypes)
{
    if (target == null)
    {
        throw new ArgumentNullException(
            nameof(target));
    }

    if (string.IsNullOrWhiteSpace(targetType))
    {
        return [];
    }

    if (relationshipTypes == null ||
        relationshipTypes.Length == 0)
    {
        return TypeEquals(
                target,
                targetType)
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
        if (string.IsNullOrWhiteSpace(
                relationshipType))
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
            DistinctResources(
                next);

        if (current.Count == 0)
        {
            return [];
        }
    }

    return current
        .Where(
            resource =>
                TypeEquals(
                    resource,
                    targetType))
        .OrderBy(
            resource =>
                resource.Name,
            StringComparer.OrdinalIgnoreCase)
        .ToList();
}

// =========================================================
// HELPERS
// =========================================================

private static List<AzureResource>
    DistinctResources(
        IEnumerable<AzureResource> resources)
{
    return resources
        .Where(
            resource =>
                resource != null &&
                !string.IsNullOrWhiteSpace(
                    resource.Id))
        .GroupBy(
            resource =>
                NormalizeId(resource.Id),
            StringComparer.OrdinalIgnoreCase)
        .Select(
            group =>
                group.First())
        .OrderBy(
            resource =>
                resource.Name,
            StringComparer.OrdinalIgnoreCase)
        .ToList();
}

private static bool TypeEquals(
    AzureResource resource,
    string type)
{
    return string.Equals(
        resource.Type,
        type,
        StringComparison.OrdinalIgnoreCase);
}

private static string NormalizeId(
    string id)
{
    return id
        .Trim()
        .TrimEnd('/');
}

}
