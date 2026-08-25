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

public sealed record ScannerExecution(string Scanner, string Version, string Status, int Findings, long DurationMs, string? Error = null);
public sealed record AdvisoryRecord(string Id, string Package, string Ecosystem, string? AffectedRange, Severity Severity,
    string Summary, string[] Aliases, DateTimeOffset ModifiedAt, string Source = "OSV");
public sealed record DetectionRule(string Id, string Scanner, string Category, Severity DefaultSeverity, string Description,
    string Version, bool Enabled = true);
public sealed record ScanEnvelope(Guid Id, Guid RepositoryId, string Trigger, string Ref, DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt, string Status, int FilesScanned, IReadOnlyList<Finding> Findings,
    IReadOnlyList<ScannerExecution> Scanners, PolicyResult Policy, string? SbomPath = null);
public sealed record WebhookJob(Guid Id, string DeliveryId, string Event, string Repository, string CloneUrl, string Ref,
    long InstallationId, string Status, DateTimeOffset CreatedAt, string? Error = null);

public sealed record Policy(int MaxCritical = 0, int MaxHigh = 0, bool BlockSecrets = true);
public sealed record PolicyResult(bool Passed, IReadOnlyList<string> Violations);
public sealed class DataState(List<RepositoryRecord> repositories, List<ScanRecord> scans, Policy policy)
{
    public List<RepositoryRecord> Repositories { get; set; } = repositories;
    public List<ScanRecord> Scans { get; set; } = scans;
    public Policy Policy { get; set; } = policy;
    public List<ScanEnvelope> V2Scans { get; set; } = [];
    public List<AdvisoryRecord> Advisories { get; set; } = [];
    public List<DetectionRule> Rules { get; set; } = [];
    public List<WebhookJob> WebhookJobs { get; set; } = [];
}

public sealed record AddRepositoryRequest(string Name, string Path);
public sealed record ScanRequest(string? Commit = null);
public sealed record UpdateFindingRequest(FindingStatus Status);
