namespace RepoGuard.Api.Engine;

public sealed class DetectionEngine(IEnumerable<IScannerAdapter> scanners, RepositoryAnalyzer native,
    OsvAdvisoryService osv, JsonStore store, IConfiguration configuration)
{
    public async Task<ScanEnvelope> Scan(Guid repositoryId, string root, string trigger, string reference, CancellationToken ct)
    {
        var started=DateTimeOffset.UtcNow;var artifactRoot=Path.GetFullPath(configuration["REPOGUARD_ARTIFACTS"]??"data/artifacts");var scanId=Guid.NewGuid();var artifacts=Path.Combine(artifactRoot,scanId.ToString("N"));Directory.CreateDirectory(artifacts);
        var all=new List<Finding>();var executions=new List<ScannerExecution>();var nativeClock=System.Diagnostics.Stopwatch.StartNew();var nativeResult=await native.Analyze(root,ct);all.AddRange(nativeResult.Findings);executions.Add(new("native","2.0.0","completed",nativeResult.Findings.Count,nativeClock.ElapsedMilliseconds));
        string? sbom=null;
        foreach(var scanner in scanners.OrderBy(x=>x.Name=="syft"?0:x.Name=="grype"?2:1))
        {
            var result=await scanner.ScanAsync(new(root,artifacts,ct));all.AddRange(result.Findings);sbom=result.SbomPath??sbom;executions.Add(new(result.Name,result.Version,result.Status,result.Findings.Count,result.DurationMs,result.Error));
        }
        var osvFindings=await osv.EnrichFromSbom(sbom,ct);all.AddRange(osvFindings);executions.Add(new("osv","v1",osvFindings.Count>0?"completed":"completed",osvFindings.Count,0));
        var normalized=all.GroupBy(x=>x.Fingerprint).Select(g=>g.OrderByDescending(x=>x.Severity).First()).OrderByDescending(x=>x.Severity).ToList();var state=await store.Read(ct);var policy=RepositoryAnalyzer.Evaluate(normalized,state.Policy);var envelope=new ScanEnvelope(scanId,repositoryId,trigger,reference,started,DateTimeOffset.UtcNow,policy.Passed?"passed":"failed",nativeResult.Files,normalized,executions,policy,sbom is null?null:Path.GetRelativePath(artifactRoot,sbom).Replace('\\','/'));
        await store.Mutate(s=>{s.V2Scans.Add(envelope);return 0;},ct);return envelope;
    }
}
