using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace RepoGuard.Api.Engine;

public sealed record ScanContext(string Root, string ArtifactDirectory, CancellationToken CancellationToken);
public sealed record ScannerResult(string Name, string Version, IReadOnlyList<Finding> Findings, string Status,
    long DurationMs, string? Error = null, string? SbomPath = null);
public interface IScannerAdapter
{
    string Name { get; }
    Task<ScannerResult> ScanAsync(ScanContext context);
}

public sealed class SafeCommandRunner
{
    private const int MaxOutputChars = 20_000_000;
    public async Task<CommandResult> Run(string executable, IEnumerable<string> arguments, string workingDirectory,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var start = new ProcessStartInfo(executable) {
            WorkingDirectory = workingDirectory, RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = new Process { StartInfo = start };
        var clock = Stopwatch.StartNew();
        try
        {
            process.Start();
            var stdoutTask = ReadBounded(process.StandardOutput, timeoutSource.Token);
            var stderrTask = ReadBounded(process.StandardError, timeoutSource.Token);
            await process.WaitForExitAsync(timeoutSource.Token);
            return new(process.ExitCode, await stdoutTask, await stderrTask, clock.ElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(true); } catch (InvalidOperationException) { }
            return new(-1, "", "Scanner timed out.", clock.ElapsedMilliseconds);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return new(-127, "", "Scanner executable is not installed.", clock.ElapsedMilliseconds);
        }
    }

    private static async Task<string> ReadBounded(StreamReader reader, CancellationToken ct)
    {
        var buffer = new char[8192]; var result = new StringBuilder();
        while (true) { var read = await reader.ReadAsync(buffer, ct); if (read == 0) break; if (result.Length + read > MaxOutputChars) throw new InvalidDataException("Scanner output exceeded safety limit."); result.Append(buffer, 0, read); }
        return result.ToString();
    }
}
public sealed record CommandResult(int ExitCode, string Stdout, string Stderr, long DurationMs);

public static class FindingFactory
{
    public static Finding Create(string scanner, string rule, string category, Severity severity, string title,
        string description, string file, int line, string remediation)
    {
        var evidence = $"{scanner}|{rule}|{file.Replace('\\','/')}|{line}|{title}";
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(evidence));
        return new(Convert.ToHexString(hash).ToLowerInvariant()[..24], $"{scanner.ToUpperInvariant()}-{rule}", category,
            severity, title, description, file.Replace('\\','/'), Math.Max(1, line), remediation);
    }

    public static Severity SeverityOf(string? value) => value?.ToUpperInvariant() switch {
        "CRITICAL" or "ERROR" => Severity.Critical, "HIGH" => Severity.High,
        "MEDIUM" or "MODERATE" or "WARNING" => Severity.Medium, "LOW" => Severity.Low, _ => Severity.Info };
    public static string? String(JsonElement node, params string[] names)
    {
        foreach (var name in names) if (node.ValueKind == JsonValueKind.Object && node.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String) return p.GetString(); return null;
    }
    public static int Int(JsonElement node, params string[] names)
    {
        foreach (var name in names) if (node.ValueKind == JsonValueKind.Object && node.TryGetProperty(name, out var p) && p.TryGetInt32(out var value)) return value; return 1;
    }
}
