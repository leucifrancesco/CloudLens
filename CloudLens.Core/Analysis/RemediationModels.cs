namespace CloudLens.Core.Analysis;

public enum RemediationActionType
{
    AzureCli,
    AzurePowerShell,
    Manual,
    Informational
}

public enum RemediationStatus
{
    Ready,
    ReviewRequired,
    NotAutomatable
}

public sealed record RemediationAction(
    string Id,
    string FindingId,
    string RuleId,
    Category Category,
    Severity Severity,
    string Title,
    string Description,
    string ResourceName,
    string ResourceType,
    string? ResourceId,
    RemediationActionType ActionType,
    RemediationStatus Status,
    string Action,
    string? Command,
    bool RequiresReview);

public sealed class RemediationPlan
{
    public IReadOnlyList<RemediationAction> Actions { get; init; } = [];

    public int TotalActions =>
        Actions.Count;

    public int ReadyActions =>
        Actions.Count(
            action =>
                action.Status == RemediationStatus.Ready);

    public int ReviewRequiredActions =>
        Actions.Count(
            action =>
                action.Status == RemediationStatus.ReviewRequired);

    public int NotAutomatableActions =>
        Actions.Count(
            action =>
                action.Status == RemediationStatus.NotAutomatable);

    public int CriticalActions =>
        Actions.Count(
            action =>
                action.Severity == Severity.Critical);

    public int HighActions =>
        Actions.Count(
            action =>
                action.Severity == Severity.High);

    public int MediumActions =>
        Actions.Count(
            action =>
                action.Severity == Severity.Medium);

    public int LowActions =>
        Actions.Count(
            action =>
                action.Severity == Severity.Low);

    public Dictionary<Category, int> ActionsByCategory =>
        Actions
            .GroupBy(action => action.Category)
            .ToDictionary(
                group => group.Key,
                group => group.Count());
}