using System.Net.Http.Json;
using System.Text.Json;

namespace RepoGuard.Api.Engine;

public sealed class OsvAdvisoryService(HttpClient http, JsonStore store, ILogger<OsvAdvisoryService> logger)
{
    public async Task<IReadOnlyList<Finding>> EnrichFromSbom(string? sbomPath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(sbomPath) || !File.Exists(sbomPath)) return [];
        using var doc=JsonDocument.Parse(await File.ReadAllTextAsync(sbomPath,ct));
        if(!doc.RootElement.TryGetProperty("components",out var components)) return [];
        var packages=components.EnumerateArray().Select(x=>new { Name=FindingFactory.String(x,"name"), Version=FindingFactory.String(x,"version"), Purl=FindingFactory.String(x,"purl") }).Where(x=>x.Name is not null&&x.Version is not null&&x.Purl is not null).Take(1000).ToList();
        var queries=packages.Select(x=>new { package=new { purl=x.Purl }, version=x.Version }).ToArray();
        if(queries.Length==0)return [];
        try
        {
            using var response=await http.PostAsJsonAsync("v1/querybatch",new { queries },ct); response.EnsureSuccessStatusCode();
            using var payload=JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct)); var findings=new List<Finding>();var advisories=new List<AdvisoryRecord>();var results=payload.RootElement.GetProperty("results").EnumerateArray().ToArray();
            for(var i=0;i<results.Length;i++)if(results[i].TryGetProperty("vulns",out var vulns))foreach(var summary in vulns.EnumerateArray())
            {
                var id=FindingFactory.String(summary,"id")??"OSV"; using var detailResponse=await http.GetAsync($"v1/vulns/{Uri.EscapeDataString(id)}",ct); if(!detailResponse.IsSuccessStatusCode)continue;using var detail=JsonDocument.Parse(await detailResponse.Content.ReadAsStringAsync(ct));var root=detail.RootElement;
                var severity=SeverityFromOsv(root);var text=FindingFactory.String(root,"summary","details")??"Known open-source vulnerability.";var aliases=root.TryGetProperty("aliases",out var aliasNode)?aliasNode.EnumerateArray().Select(x=>x.GetString()??"").Where(x=>x.Length>0).ToArray():[];
                advisories.Add(new(id,packages[i].Name!,"unknown",null,severity,text,aliases,DateTimeOffset.TryParse(FindingFactory.String(root,"modified"),out var modified)?modified:DateTimeOffset.UtcNow));
                findings.Add(FindingFactory.Create("osv",id,"dependency",severity,id,text,packages[i].Name!,1,$"Upgrade {packages[i].Name} from {packages[i].Version} to a version outside affected ranges."));
            }
            await store.Mutate(state=>{foreach(var advisory in advisories){state.Advisories.RemoveAll(x=>x.Id==advisory.Id&&x.Package==advisory.Package);state.Advisories.Add(advisory);}return 0;},ct);
            return findings;
        }
        catch(Exception ex) when(ex is HttpRequestException or JsonException or TaskCanceledException){logger.LogWarning("OSV enrichment unavailable: {Type}",ex.GetType().Name);return [];}
    }
    private static Severity SeverityFromOsv(JsonElement root){if(root.TryGetProperty("database_specific",out var db)&&db.TryGetProperty("severity",out var s))return FindingFactory.SeverityOf(s.GetString());return Severity.High;}
}
