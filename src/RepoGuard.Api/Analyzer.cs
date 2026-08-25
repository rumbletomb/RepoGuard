using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RepoGuard.Api;

public sealed partial class RepositoryAnalyzer
{
    private const long MaxFileBytes = 2 * 1024 * 1024;
    private const int MaxFiles = 20_000;
    private static readonly HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase)
        { ".git", "node_modules", "bin", "obj", "vendor", ".next", "dist", "coverage" };

    public async Task<(IReadOnlyList<Finding> Findings, int Files)> Analyze(string repositoryPath, CancellationToken ct)
    {
        var root = Path.GetFullPath(repositoryPath);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException("Repository path does not exist.");
        var findings = new List<Finding>();
        var files = EnumerateSafe(root).Take(MaxFiles + 1).ToList();
        if (files.Count > MaxFiles) throw new InvalidOperationException($"Repository exceeds the {MaxFiles} file safety limit.");

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var info = new FileInfo(file);
            if (info.Length > MaxFileBytes || IsBinary(file)) continue;
            string text;
            try { text = await File.ReadAllTextAsync(file, ct); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            AnalyzeFile(relative, text, findings);
        }
        return (findings.GroupBy(x => x.Fingerprint).Select(x => x.First()).ToList(), files.Count);
    }

    public static PolicyResult Evaluate(IReadOnlyList<Finding> findings, Policy policy)
    {
        var open = findings.Where(x => x.Status == FindingStatus.Open).ToList();
        var violations = new List<string>();
        var critical = open.Count(x => x.Severity == Severity.Critical);
        var high = open.Count(x => x.Severity == Severity.High);
        if (critical > policy.MaxCritical) violations.Add($"Critical findings: {critical} (maximum {policy.MaxCritical}).");
        if (high > policy.MaxHigh) violations.Add($"High findings: {high} (maximum {policy.MaxHigh}).");
        if (policy.BlockSecrets && open.Any(x => x.Category == "secret")) violations.Add("Exposed secrets are forbidden.");
        return new(violations.Count == 0, violations);
    }

    private static void AnalyzeFile(string file, string text, List<Finding> output)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            AddMatches(PrivateKey(), line, file, i + 1, "RG001", "secret", Severity.Critical,
                "Private key committed", "Private key material is present in the repository.", "Revoke the key, remove it from history, and load it from a secret manager.", output);
            AddMatches(AwsKey(), line, file, i + 1, "RG002", "secret", Severity.Critical,
                "Possible AWS access key", "A value matching an AWS access-key identifier was found.", "Revoke and rotate the credential; use workload identity or a secret manager.", output);
            AddMatches(GenericSecret(), line, file, i + 1, "RG003", "secret", Severity.High,
                "Hard-coded credential", "A credential-like assignment contains a literal value.", "Read credentials from a secret manager or environment injection.", output);
            AddMatches(SqlConcat(), line, file, i + 1, "RG101", "sast", Severity.High,
                "Possible SQL injection", "SQL text appears to be built using string concatenation or interpolation.", "Use a parameterized query or an ORM parameter API.", output);
            AddMatches(EvalCall(), line, file, i + 1, "RG102", "sast", Severity.High,
                "Dynamic code execution", "Dynamic evaluation may execute attacker-controlled input.", "Replace dynamic execution with an explicit parser or allow-list.", output);
            AddMatches(InsecureHttp(), line, file, i + 1, "RG201", "configuration", Severity.Medium,
                "Insecure HTTP endpoint", "An unencrypted HTTP URL is configured.", "Use HTTPS and validate the peer certificate.", output);
            AddMatches(DockerLatest(), line, file, i + 1, "RG301", "container", Severity.Medium,
                "Unpinned container image", "The Docker base image uses the mutable latest tag.", "Pin an immutable version or digest.", output);
            AddMatches(PrivilegedContainer(), line, file, i + 1, "RG302", "container", Severity.High,
                "Privileged container", "A container is configured with privileged access.", "Remove privileged mode and grant only required capabilities.", output);
        }
    }

    private static void AddMatches(Regex pattern, string line, string file, int number, string rule, string category,
        Severity severity, string title, string description, string remediation, List<Finding> output)
    {
        if (!pattern.IsMatch(line)) return;
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{rule}|{file}|{line.Trim()}"))).ToLowerInvariant()[..24];
        output.Add(new(fingerprint, rule, category, severity, title, description, file, number, remediation));
    }

    private static IEnumerable<string> EnumerateSafe(string root) => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
        .Where(path => !path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(Ignored.Contains));

    private static bool IsBinary(string file)
    {
        var extensions = new[] { ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".dll", ".exe", ".woff", ".ico" };
        return extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase);
    }

    [GeneratedRegex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")]
    private static partial Regex PrivateKey();
    [GeneratedRegex(@"\bAKIA[0-9A-Z]{16}\b")]
    private static partial Regex AwsKey();
    [GeneratedRegex("""(?i)\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*["'](?!\$\{|%|<|REDACTED|example|test)[^"']{8,}["']""")]
    private static partial Regex GenericSecret();
    [GeneratedRegex(@"(?i)(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+\s*\w+|\$\{[^}]+\})")]
    private static partial Regex SqlConcat();
    [GeneratedRegex(@"\b(?:eval|exec)\s*\(")]
    private static partial Regex EvalCall();
    [GeneratedRegex(@"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)")]
    private static partial Regex InsecureHttp();
    [GeneratedRegex(@"(?i)^\s*FROM\s+\S+:latest\s*$")]
    private static partial Regex DockerLatest();
    [GeneratedRegex(@"(?i)privileged\s*:\s*true")]
    private static partial Regex PrivilegedContainer();
}
