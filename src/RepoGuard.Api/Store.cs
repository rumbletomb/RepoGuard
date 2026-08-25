using System.Text.Json;

namespace RepoGuard.Api;

public sealed class JsonStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public JsonStore(IConfiguration configuration)
    {
        _path = Path.GetFullPath(configuration["REPOGUARD_DATA"] ?? "data/repoguard.json");
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
    }

    public async Task<DataState> Read(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try { return await ReadUnsafe(ct); }
        finally { _gate.Release(); }
    }

    public async Task<T> Mutate<T>(Func<DataState, T> mutation, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var state = await ReadUnsafe(ct);
            var result = mutation(state);
            var temp = _path + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(state, Json), ct);
            File.Move(temp, _path, true);
            return result;
        }
        finally { _gate.Release(); }
    }

    private async Task<DataState> ReadUnsafe(CancellationToken ct)
    {
        if (!File.Exists(_path)) { var fresh=new DataState([], [], new Policy()); fresh.Rules.AddRange(DefaultRules()); return fresh; }
        var json = await File.ReadAllTextAsync(_path, ct);
        var state=JsonSerializer.Deserialize<DataState>(json, Json) ?? new([], [], new Policy());
        if(state.Rules.Count==0)state.Rules.AddRange(DefaultRules());
        return state;
    }

    private static IEnumerable<DetectionRule> DefaultRules() =>
    [
        new("native-v2","native","sast",Severity.High,"Built-in deterministic baseline rules.","2.0.0"),
        new("gitleaks","gitleaks","secret",Severity.High,"Credential and secret patterns.","external"),
        new("semgrep-auto","semgrep","sast",Severity.High,"Language-aware static analysis.","external"),
        new("trivy-fs","trivy","dependency",Severity.High,"Dependencies, secrets and misconfiguration.","external"),
        new("checkov-iac","checkov","iac",Severity.High,"Terraform, Kubernetes and cloud IaC policies.","external"),
        new("syft-cdx","syft","sbom",Severity.Info,"CycloneDX software bill of materials.","external"),
        new("grype-sbom","grype","dependency",Severity.High,"SBOM vulnerability matching.","external"),
        new("osv-v1","osv","dependency",Severity.High,"Live OSV advisory correlation.","v1")
    ];
}
