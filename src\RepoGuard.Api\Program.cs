using System.Text.Json.Serialization;
using RepoGuard.Api;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddSingleton<JsonStore>();
builder.Services.AddSingleton<RepositoryAnalyzer>();
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();
app.UseDefaultFiles();
app.UseStaticFiles();

var api = app.MapGroup("/api");
api.MapGet("/health", () => Results.Ok(new { status = "healthy", version = "1.0.0" }));
api.MapGet("/dashboard", async (JsonStore store, CancellationToken ct) =>
{
    var state = await store.Read(ct);
    var last = state.Scans.OrderByDescending(x => x.CompletedAt).FirstOrDefault();
    return Results.Ok(new {
        repositories = state.Repositories.Count, scans = state.Scans.Count,
        openFindings = last?.Findings.Count(x => x.Status == FindingStatus.Open) ?? 0,
        critical = last?.Findings.Count(x => x.Status == FindingStatus.Open && x.Severity == Severity.Critical) ?? 0,
        policyPassed = last?.Policy.Passed, latestScan = last
    });
});
api.MapGet("/repositories", async (JsonStore store, CancellationToken ct) => Results.Ok((await store.Read(ct)).Repositories));
api.MapPost("/repositories", async (AddRepositoryRequest request, JsonStore store, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.Name) || string.IsNullOrWhiteSpace(request.Path))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["repository"] = ["Name and path are required."] });
    var fullPath = Path.GetFullPath(request.Path);
    if (!Directory.Exists(fullPath)) return Results.NotFound(new { error = "Repository directory does not exist." });
    var repo = new RepositoryRecord(Guid.NewGuid(), request.Name.Trim(), fullPath, DateTimeOffset.UtcNow);
    await store.Mutate(state => { state.Repositories.Add(repo); return repo; }, ct);
    return Results.Created($"/api/repositories/{repo.Id}", repo);
});
api.MapDelete("/repositories/{id:guid}", async (Guid id, JsonStore store, CancellationToken ct) =>
{
    var removed = await store.Mutate(state => state.Repositories.RemoveAll(x => x.Id == id) > 0, ct);
    return removed ? Results.NoContent() : Results.NotFound();
});
api.MapPost("/repositories/{id:guid}/scans", async (Guid id, ScanRequest request, JsonStore store, RepositoryAnalyzer analyzer, CancellationToken ct) =>
{
    var state = await store.Read(ct);
    var repo = state.Repositories.FirstOrDefault(x => x.Id == id);
    if (repo is null) return Results.NotFound(new { error = "Repository not found." });
    var started = DateTimeOffset.UtcNow;
    var result = await analyzer.Analyze(repo.Path, ct);
    var policyResult = RepositoryAnalyzer.Evaluate(result.Findings, state.Policy);
    var scan = new ScanRecord(Guid.NewGuid(), id, started, DateTimeOffset.UtcNow, request.Commit ?? "working-tree",
        policyResult.Passed ? "passed" : "failed", result.Files, result.Findings, policyResult);
    await store.Mutate(s => { s.Scans.Add(scan); return scan; }, ct);
    return Results.Ok(scan);
});
api.MapGet("/scans", async (JsonStore store, CancellationToken ct) =>
    Results.Ok((await store.Read(ct)).Scans.OrderByDescending(x => x.CompletedAt)));
api.MapGet("/scans/{id:guid}", async (Guid id, JsonStore store, CancellationToken ct) =>
    (await store.Read(ct)).Scans.FirstOrDefault(x => x.Id == id) is { } scan ? Results.Ok(scan) : Results.NotFound());
api.MapGet("/scans/{id:guid}/sarif", async (Guid id, JsonStore store, CancellationToken ct) =>
    (await store.Read(ct)).Scans.FirstOrDefault(x => x.Id == id) is { } scan ? Results.Ok(SarifExporter.Create(scan)) : Results.NotFound());
api.MapPut("/policy", async (Policy policy, JsonStore store, CancellationToken ct) =>
{
    if (policy.MaxCritical < 0 || policy.MaxHigh < 0) return Results.BadRequest(new { error = "Thresholds cannot be negative." });
    return Results.Ok(await store.Mutate(state => { state.Policy = policy; return policy; }, ct));
});
api.MapGet("/policy", async (JsonStore store, CancellationToken ct) => Results.Ok((await store.Read(ct)).Policy));

app.MapFallbackToFile("index.html");
app.Run();

public partial class Program;
