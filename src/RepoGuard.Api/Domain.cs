namespace RepoGuard.Api;

public enum Severity { Info, Low, Medium, High, Critical }
public enum FindingStatus { Open, Accepted, Resolved }

public sealed record RepositoryRecord(Guid Id, string Name, string Path, DateTimeOffset CreatedAt);

public sealed record Finding(
    string Fingerprint, string RuleId, string Category, Severity Severity,
    string Title, string Description, string File, int Line,
    string Remediation, FindingStatus Status = FindingStatus.Open);

public sealed record ScanRecord(
    Guid Id, Guid RepositoryId, DateTimeOffset StartedAt, DateTimeOffset CompletedAt,
    string Commit, string Status, int FilesScanned, IReadOnlyList<Finding> Findings,
    PolicyResult Policy);

public sealed record Policy(int MaxCritical = 0, int MaxHigh = 0, bool BlockSecrets = true);
public sealed record PolicyResult(bool Passed, IReadOnlyList<string> Violations);
public sealed class DataState(List<RepositoryRecord> repositories, List<ScanRecord> scans, Policy policy)
{
    public List<RepositoryRecord> Repositories { get; set; } = repositories;
    public List<ScanRecord> Scans { get; set; } = scans;
    public Policy Policy { get; set; } = policy;
}

public sealed record AddRepositoryRequest(string Name, string Path);
public sealed record ScanRequest(string? Commit = null);
public sealed record UpdateFindingRequest(FindingStatus Status);
