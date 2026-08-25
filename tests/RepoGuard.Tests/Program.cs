using RepoGuard.Api;

var tests = new List<(string, Func<Task>)>
{
    ("detects secrets and unsafe code", DetectsFindings),
    ("ignores generated directories", IgnoresGenerated),
    ("policy blocks critical findings", PolicyBlocks),
    ("policy accepts clean scan", PolicyPasses),
    ("fingerprints are stable", StableFingerprint),
    ("SARIF contains rule and location", SarifIsValid)
};
var failed = 0;
foreach (var (name, test) in tests)
{
    try { await test(); Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failed++; Console.WriteLine($"FAIL {name}: {ex.Message}"); }
}
Console.WriteLine($"{tests.Count - failed}/{tests.Count} tests passed");
return failed;

static async Task DetectsFindings()
{
    using var repo = TempRepo.Create(("app.py", "password = \"real-password-123\"\neval(user_input)\n"));
    var (findings, files) = await new RepositoryAnalyzer().Analyze(repo.Path, default);
    Assert(files == 1, "Expected one file");
    Assert(findings.Any(x => x.RuleId == "RG003"), "Secret was not detected");
    Assert(findings.Any(x => x.RuleId == "RG102"), "eval was not detected");
}
static async Task IgnoresGenerated()
{
    using var repo = TempRepo.Create(("node_modules/pkg/x.js", "password = \"hidden-secret-123\""), ("safe.js", "const ok = true;"));
    var (findings, _) = await new RepositoryAnalyzer().Analyze(repo.Path, default);
    Assert(findings.Count == 0, "Ignored directory produced findings");
}
static Task PolicyBlocks()
{
    var finding = new Finding("x", "RG001", "secret", Severity.Critical, "x", "x", "x", 1, "x");
    var result = RepositoryAnalyzer.Evaluate([finding], new Policy());
    Assert(!result.Passed && result.Violations.Count == 2, "Expected critical and secret violations"); return Task.CompletedTask;
}
static Task PolicyPasses()
{
    var result = RepositoryAnalyzer.Evaluate([], new Policy()); Assert(result.Passed, "Clean scan should pass"); return Task.CompletedTask;
}
static async Task StableFingerprint()
{
    using var repo = TempRepo.Create(("a.py", "eval(user_input)")); var a = new RepositoryAnalyzer();
    var one = await a.Analyze(repo.Path, default); var two = await a.Analyze(repo.Path, default);
    Assert(one.Findings.Single().Fingerprint == two.Findings.Single().Fingerprint, "Fingerprint changed");
}
static Task SarifIsValid()
{
    var finding = new Finding("x", "RG101", "sast", Severity.High, "SQL", "unsafe", "a.cs", 7, "parameterize");
    var scan = new ScanRecord(Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "abc", "failed", 1, [finding], new(false,["x"]));
    var json = System.Text.Json.JsonSerializer.Serialize(SarifExporter.Create(scan));
    Assert(json.Contains("2.1.0") && json.Contains("RG101") && json.Contains("startLine"), "Invalid SARIF structure"); return Task.CompletedTask;
}
static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }

sealed class TempRepo : IDisposable
{
    public string Path { get; }
    private TempRepo(string path) => Path = path;
    public static TempRepo Create(params (string Name, string Content)[] files)
    {
        var root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "repoguard-tests", Guid.NewGuid().ToString("N"));
        foreach (var file in files) { var path = System.IO.Path.Combine(root, file.Name); Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!); File.WriteAllText(path, file.Content); }
        return new(root);
    }
    public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
}
