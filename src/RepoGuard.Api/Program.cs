using System.Text.Json.Serialization;
using RepoGuard.Api;
using RepoGuard.Api.Engine;
using RepoGuard.Api.GitHub;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddSingleton<JsonStore>();
builder.Services.AddSingleton<RepositoryAnalyzer>();
builder.Services.AddSingleton<SafeCommandRunner>();
builder.Services.AddSingleton<IScannerAdapter, SyftScanner>();
builder.Services.AddSingleton<IScannerAdapter, GitleaksScanner>();
builder.Services.AddSingleton<IScannerAdapter, SemgrepScanner>();
builder.Services.AddSingleton<IScannerAdapter, TrivyScanner>();
builder.Services.AddSingleton<IScannerAdapter, CheckovScanner>();
builder.Services.AddSingleton<IScannerAdapter, GrypeScanner>();
builder.Services.AddHttpClient<OsvAdvisoryService>(client => { client.BaseAddress = new Uri("https://api.osv.dev/"); client.Timeout = TimeSpan.FromSeconds(60); });
builder.Services.AddSingleton<DetectionEngine>();
builder.Services.AddSingleton<WebhookQueue>();
builder.Services.AddHttpClient<GitHubInstallationTokenProvider>(client => { client.BaseAddress = new Uri("https://api.github.com/"); client.DefaultRequestHeaders.UserAgent.ParseAdd("RepoGuard/2.0"); });
builder.Services.AddHostedService<WebhookWorker>();
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler();
app.UseDefaultFiles();
app.UseStaticFiles();

var api = app.MapGroup("/api");
api.MapGet("/health", () => Results.Ok(new { status = "healthy", version = "2.0.0", engine = "multi-scanner" }));
api.MapGet("/dashboard", async (JsonStore store, CancellationToken ct) =>
{
    var state = await store.Read(ct);
    var last = state.V2Scans.OrderByDescending(x => x.CompletedAt).FirstOrDefault();
    return Results.Ok(new {
        repositories = state.Repositories.Count, scans = state.Scans.Count,
        openFindings = last?.Findings.Count(x => x.Status == FindingStatus.Open) ?? 0,
        critical = last?.Findings.Count(x => x.Status == FindingStatus.Open && x.Severity == Severity.Critical) ?? 0,
        policyPassed = last?.Policy.Passed, latestScan = last, scanners = last?.Scanners
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
api.MapPost("/v2/repositories/{id:guid}/scans", async (Guid id, ScanRequest request, JsonStore store, DetectionEngine engine, CancellationToken ct) =>
{
    var state=await store.Read(ct);var repo=state.Repositories.FirstOrDefault(x=>x.Id==id);if(repo is null)return Results.NotFound(new{error="Repository not found."});
    return Results.Ok(await engine.Scan(id,repo.Path,"manual",request.Commit??"working-tree",ct));
});
api.MapGet("/v2/scans", async (JsonStore store,CancellationToken ct)=>Results.Ok((await store.Read(ct)).V2Scans.OrderByDescending(x=>x.CompletedAt)));
api.MapGet("/v2/scans/{id:guid}", async (Guid id,JsonStore store,CancellationToken ct)=>(await store.Read(ct)).V2Scans.FirstOrDefault(x=>x.Id==id) is{} scan?Results.Ok(scan):Results.NotFound());
api.MapGet("/v2/scans/{id:guid}/sarif", async (Guid id,JsonStore store,CancellationToken ct)=>
{
    var scan=(await store.Read(ct)).V2Scans.FirstOrDefault(x=>x.Id==id);if(scan is null)return Results.NotFound();var compatible=new ScanRecord(scan.Id,scan.RepositoryId,scan.StartedAt,scan.CompletedAt,scan.Ref,scan.Status,scan.FilesScanned,scan.Findings,scan.Policy);return Results.Ok(SarifExporter.Create(compatible));
});
api.MapGet("/v2/scans/{id:guid}/sbom", async (Guid id,JsonStore store,IConfiguration config,CancellationToken ct)=>
{
    var scan=(await store.Read(ct)).V2Scans.FirstOrDefault(x=>x.Id==id);if(scan?.SbomPath is null)return Results.NotFound();var root=Path.GetFullPath(config["REPOGUARD_ARTIFACTS"]??"data/artifacts");var path=Path.GetFullPath(Path.Combine(root,scan.SbomPath));if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||!File.Exists(path))return Results.NotFound();return Results.File(path,"application/vnd.cyclonedx+json",$"repoguard-{id}.cdx.json");
});
api.MapGet("/v2/advisories", async (string? query,JsonStore store,CancellationToken ct)=>{var items=(await store.Read(ct)).Advisories.AsEnumerable();if(!string.IsNullOrWhiteSpace(query))items=items.Where(x=>x.Id.Contains(query,StringComparison.OrdinalIgnoreCase)||x.Package.Contains(query,StringComparison.OrdinalIgnoreCase));return Results.Ok(items.OrderByDescending(x=>x.ModifiedAt));});
api.MapGet("/v2/rules", async (JsonStore store,CancellationToken ct)=>Results.Ok((await store.Read(ct)).Rules));
api.MapGet("/v2/webhook-jobs", async (JsonStore store,CancellationToken ct)=>Results.Ok((await store.Read(ct)).WebhookJobs.OrderByDescending(x=>x.CreatedAt)));
api.MapPost("/webhooks/github", async (HttpRequest request,WebhookQueue queue,JsonStore store,IConfiguration config,CancellationToken ct)=>
{
    var secret=config["GitHub:WebhookSecret"];if(string.IsNullOrWhiteSpace(secret))return Results.Problem("GitHub webhook secret is not configured.",statusCode:503);
    if(request.ContentLength is>10_000_000)return Results.StatusCode(413);using var memory=new MemoryStream();await request.Body.CopyToAsync(memory,ct);var body=memory.ToArray();
    if(!GitHubWebhookParser.Verify(body,request.Headers["X-Hub-Signature-256"].FirstOrDefault(),secret))return Results.Unauthorized();
    var delivery=request.Headers["X-GitHub-Delivery"].FirstOrDefault()??Guid.NewGuid().ToString("N");var eventName=request.Headers["X-GitHub-Event"].FirstOrDefault()??"unknown";var job=GitHubWebhookParser.Parse(delivery,eventName,body);if(job is null)return Results.Accepted();
    var duplicate=(await store.Read(ct)).WebhookJobs.Any(x=>x.DeliveryId==delivery);if(duplicate)return Results.Ok(new{status="duplicate",delivery});if(!queue.Enqueue(job))return Results.StatusCode(429);await store.Mutate(s=>{s.WebhookJobs.Add(job);return 0;},ct);return Results.Accepted("/api/v2/webhook-jobs",new{job.Id,status="queued"});
});

app.MapFallbackToFile("index.html");
app.Run();

public partial class Program;
