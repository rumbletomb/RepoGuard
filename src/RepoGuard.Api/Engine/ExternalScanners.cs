using System.Text.Json;

namespace RepoGuard.Api.Engine;

public abstract class JsonScanner(SafeCommandRunner runner)
{
    protected SafeCommandRunner Runner { get; } = runner;
    protected static ScannerResult Missing(string name, CommandResult command) => new(name, "unavailable", [], "unavailable", command.DurationMs, command.Stderr);
    protected static JsonDocument Parse(string json) => JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json,
        new JsonDocumentOptions { MaxDepth = 128, AllowTrailingCommas = true });
}

public sealed class GitleaksScanner(SafeCommandRunner runner) : JsonScanner(runner), IScannerAdapter
{
    public string Name => "gitleaks";
    public async Task<ScannerResult> ScanAsync(ScanContext c)
    {
        var output = Path.Combine(c.ArtifactDirectory, "gitleaks.json");
        var cmd = await Runner.Run("gitleaks", ["detect", "--source", c.Root, "--no-git", "--redact", "--report-format", "json", "--report-path", output, "--exit-code", "0"], c.Root, TimeSpan.FromMinutes(5), c.CancellationToken);
        if (cmd.ExitCode == -127) return Missing(Name, cmd);
        if (!File.Exists(output)) return new(Name, "unknown", [], "error", cmd.DurationMs, Sanitize(cmd.Stderr));
        using var doc = Parse(await File.ReadAllTextAsync(output, c.CancellationToken)); var findings = new List<Finding>();
        if (doc.RootElement.ValueKind == JsonValueKind.Array) foreach (var x in doc.RootElement.EnumerateArray())
            findings.Add(FindingFactory.Create(Name, FindingFactory.String(x,"RuleID") ?? "secret", "secret", Severity.High,
                FindingFactory.String(x,"Description") ?? "Secret detected", "Gitleaks detected a credential pattern.",
                FindingFactory.String(x,"File") ?? "unknown", FindingFactory.Int(x,"StartLine"), "Revoke and rotate the secret, purge history, then use a secret manager."));
        return new(Name, "external", findings, "completed", cmd.DurationMs);
    }
    private static string Sanitize(string value) => value.Length > 1000 ? value[..1000] : value;
}

public sealed class SemgrepScanner(SafeCommandRunner runner) : JsonScanner(runner), IScannerAdapter
{
    public string Name => "semgrep";
    public async Task<ScannerResult> ScanAsync(ScanContext c)
    {
        var cmd = await Runner.Run("semgrep", ["scan", "--config", "auto", "--json", "--metrics", "off", "--disable-version-check", c.Root], c.Root, TimeSpan.FromMinutes(10), c.CancellationToken);
        if (cmd.ExitCode == -127) return Missing(Name, cmd);
        try { using var doc=Parse(cmd.Stdout); var list=new List<Finding>(); if(doc.RootElement.TryGetProperty("results",out var results)) foreach(var x in results.EnumerateArray()) { var extra=x.GetProperty("extra"); var start=x.GetProperty("start"); list.Add(FindingFactory.Create(Name,FindingFactory.String(x,"check_id")??"rule","sast",FindingFactory.SeverityOf(extra.TryGetProperty("severity",out var s)?s.GetString():null),FindingFactory.String(extra,"message")??"Semgrep finding",FindingFactory.String(extra,"message")??"Static analysis finding.",FindingFactory.String(x,"path")??"unknown",FindingFactory.Int(start,"line"),"Review the rule guidance and remove the unsafe data flow.")); } return new(Name,"external",list,"completed",cmd.DurationMs); }
        catch(JsonException ex){return new(Name,"unknown",[],"error",cmd.DurationMs,ex.Message);}
    }
}

public sealed class TrivyScanner(SafeCommandRunner runner) : JsonScanner(runner), IScannerAdapter
{
    public string Name => "trivy";
    public async Task<ScannerResult> ScanAsync(ScanContext c)
    {
        var cmd=await Runner.Run("trivy",["fs","--format","json","--scanners","vuln,misconfig,secret","--quiet",c.Root],c.Root,TimeSpan.FromMinutes(10),c.CancellationToken);
        if(cmd.ExitCode==-127)return Missing(Name,cmd); try {using var doc=Parse(cmd.Stdout);var list=new List<Finding>();if(doc.RootElement.TryGetProperty("Results",out var results))foreach(var result in results.EnumerateArray()){var file=FindingFactory.String(result,"Target")??"unknown";if(result.TryGetProperty("Vulnerabilities",out var vulns)&&vulns.ValueKind==JsonValueKind.Array)foreach(var x in vulns.EnumerateArray())list.Add(FindingFactory.Create(Name,FindingFactory.String(x,"VulnerabilityID")??"CVE","dependency",FindingFactory.SeverityOf(FindingFactory.String(x,"Severity")),FindingFactory.String(x,"Title","VulnerabilityID")??"Vulnerability",FindingFactory.String(x,"Description")??"Known vulnerable dependency.",file,1,$"Upgrade {FindingFactory.String(x,"PkgName")??"the package"} to {FindingFactory.String(x,"FixedVersion")??"a fixed release"}."));if(result.TryGetProperty("Misconfigurations",out var mis)&&mis.ValueKind==JsonValueKind.Array)foreach(var x in mis.EnumerateArray())list.Add(FindingFactory.Create(Name,FindingFactory.String(x,"ID")??"MISCONFIG","iac",FindingFactory.SeverityOf(FindingFactory.String(x,"Severity")),FindingFactory.String(x,"Title")??"Misconfiguration",FindingFactory.String(x,"Description")??"Infrastructure misconfiguration.",file,x.TryGetProperty("CauseMetadata",out var cause)?FindingFactory.Int(cause,"StartLine"):1,FindingFactory.String(x,"Resolution")??"Apply the secure configuration."));}return new(Name,"external",list,"completed",cmd.DurationMs);}catch(JsonException ex){return new(Name,"unknown",[],"error",cmd.DurationMs,ex.Message);}
    }
}

public sealed class CheckovScanner(SafeCommandRunner runner) : JsonScanner(runner), IScannerAdapter
{
    public string Name=>"checkov";
    public async Task<ScannerResult> ScanAsync(ScanContext c){var cmd=await Runner.Run("checkov",["-d",c.Root,"-o","json","--quiet","--compact"],c.Root,TimeSpan.FromMinutes(10),c.CancellationToken);if(cmd.ExitCode==-127)return Missing(Name,cmd);try{using var doc=Parse(cmd.Stdout);var list=new List<Finding>();IEnumerable<JsonElement> roots=doc.RootElement.ValueKind==JsonValueKind.Array?doc.RootElement.EnumerateArray():[doc.RootElement];foreach(var root in roots)if(root.TryGetProperty("results",out var results)&&results.TryGetProperty("failed_checks",out var failed))foreach(var x in failed.EnumerateArray())list.Add(FindingFactory.Create(Name,FindingFactory.String(x,"check_id")??"CHECK","iac",Severity.High,FindingFactory.String(x,"check_name")??"IaC policy failed","Checkov infrastructure policy failed.",FindingFactory.String(x,"file_path")??"unknown",x.TryGetProperty("file_line_range",out var range)&&range.GetArrayLength()>0?range[0].GetInt32():1,FindingFactory.String(x,"guideline")??"Apply the recommended secure configuration."));return new(Name,"external",list,"completed",cmd.DurationMs);}catch(JsonException ex){return new(Name,"unknown",[],"error",cmd.DurationMs,ex.Message);}}
}

public sealed class SyftScanner(SafeCommandRunner runner) : JsonScanner(runner), IScannerAdapter
{
    public string Name=>"syft";
    public async Task<ScannerResult> ScanAsync(ScanContext c){var output=Path.Combine(c.ArtifactDirectory,"sbom.cdx.json");var cmd=await Runner.Run("syft",[c.Root,"-o",$"cyclonedx-json={output}"],c.Root,TimeSpan.FromMinutes(10),c.CancellationToken);if(cmd.ExitCode==-127)return Missing(Name,cmd);return File.Exists(output)?new(Name,"external",[],"completed",cmd.DurationMs,null,output):new(Name,"unknown",[],"error",cmd.DurationMs,"SBOM was not generated.");}
}

public sealed class GrypeScanner(SafeCommandRunner runner) : JsonScanner(runner), IScannerAdapter
{
    public string Name=>"grype";
    public async Task<ScannerResult> ScanAsync(ScanContext c){var sbom=Path.Combine(c.ArtifactDirectory,"sbom.cdx.json");var target=File.Exists(sbom)?$"sbom:{sbom}":c.Root;var cmd=await Runner.Run("grype",[target,"-o","json","--quiet"],c.Root,TimeSpan.FromMinutes(10),c.CancellationToken);if(cmd.ExitCode==-127)return Missing(Name,cmd);try{using var doc=Parse(cmd.Stdout);var list=new List<Finding>();if(doc.RootElement.TryGetProperty("matches",out var matches))foreach(var x in matches.EnumerateArray()){var vuln=x.GetProperty("vulnerability");var artifact=x.GetProperty("artifact");list.Add(FindingFactory.Create(Name,FindingFactory.String(vuln,"id")??"CVE","dependency",FindingFactory.SeverityOf(FindingFactory.String(vuln,"severity")),FindingFactory.String(vuln,"id")??"Vulnerability",$"Known vulnerability in {FindingFactory.String(artifact,"name")??"package"} {FindingFactory.String(artifact,"version")??""}.",FindingFactory.String(artifact,"name")??"sbom",1,"Upgrade to a non-affected package version."));}return new(Name,"external",list,"completed",cmd.DurationMs);}catch(JsonException ex){return new(Name,"unknown",[],"error",cmd.DurationMs,ex.Message);}}
}
