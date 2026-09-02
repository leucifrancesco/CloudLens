namespace CloudLens.Core.Azure;

public sealed record AzureResourceRelationship(
    string RelationshipType,
    string SourceResourceId,
    string TargetResourceId);