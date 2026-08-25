namespace CloudLens.Core;

public enum Severity { Critical, High, Medium, Low }
public enum Category { Security, Cost, Reliability, Performance, Operations }

public sealed record Finding(
    string Id, Category Category, Severity Severity, string RuleId, string Title,
    string Description, string Impact, string Recommendation, string ResourceName,
    string ResourceType, double MonthlySavingEur = 0, string? AzureCli = null);

public sealed class ScanStats
{
    public int Resources { get; init; } = 78;
    public int Vms { get; init; } = 6;
    public int Disks { get; init; } = 11;
    public int Nsgs { get; init; } = 4;
    public int PublicIps { get; init; } = 3;
    public int StorageAccounts { get; init; } = 5;
    public int Advisor { get; init; } = 9;
    public double MonthlyCostEur { get; init; } = 4820.55;
}

public sealed class ScanResult
{
    public string SubscriptionName { get; init; } = "DEMO — Acme S.p.A. Produzione";
    public string SubscriptionId { get; init; } = "11111111-2222-3333-4444-555555555555";
    public int Score { get; init; }
    public ScanStats Stats { get; init; } = new();
    public List<Finding> Findings { get; init; } = [];
    public Dictionary<Category,int> ScoresByCategory { get; init; } = [];
}
