using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace RepoGuard.Api.GitHub;

public sealed class WebhookQueue
{
    private readonly Channel<WebhookJob> _channel=Channel.CreateBounded<WebhookJob>(new BoundedChannelOptions(100){FullMode=BoundedChannelFullMode.DropWrite,SingleReader=true});
    public bool Enqueue(WebhookJob job)=>_channel.Writer.TryWrite(job);
    public IAsyncEnumerable<WebhookJob> ReadAll(CancellationToken ct)=>_channel.Reader.ReadAllAsync(ct);
}

public static class GitHubWebhookParser
{
    public static bool Verify(ReadOnlySpan<byte> body,string? signature,string secret)
    {
        if(string.IsNullOrWhiteSpace(signature)||!signature.StartsWith("sha256=",StringComparison.Ordinal))return false;
        var expected=HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret),body);
        try { var supplied=Convert.FromHexString(signature[7..]); return CryptographicOperations.FixedTimeEquals(expected,supplied); }
        catch (FormatException) { return false; }
    }
    public static WebhookJob? Parse(string delivery,string eventName,ReadOnlySpan<byte> body)
    {
        using var doc=JsonDocument.Parse(body.ToArray());var root=doc.RootElement;if(!root.TryGetProperty("repository",out var repo))return null;var full=repo.GetProperty("full_name").GetString()??"";var clone=repo.GetProperty("clone_url").GetString()??"";var installation=root.TryGetProperty("installation",out var install)?install.GetProperty("id").GetInt64():0;
        string reference=eventName switch{"push"=>root.GetProperty("after").GetString()??"","pull_request"=>root.GetProperty("pull_request").GetProperty("head").GetProperty("sha").GetString()??"",_=>""};if(reference.Length==0)return null;
        return new(Guid.NewGuid(),delivery,eventName,full,clone,reference,installation,"queued",DateTimeOffset.UtcNow);
    }
}

public sealed class WebhookWorker(WebhookQueue queue,JsonStore store,Engine.DetectionEngine engine,GitHubInstallationTokenProvider tokens,ILogger<WebhookWorker> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach(var job in queue.ReadAll(stoppingToken)){var current=job with{Status="running"};await Save(current,stoppingToken);var temp=Path.Combine(Path.GetTempPath(),"repoguard",job.Id.ToString("N"));try{Directory.CreateDirectory(temp);var token=job.InstallationId>0?await tokens.Get(job.InstallationId,stoppingToken):null;var runner=new Engine.SafeCommandRunner();var args=new List<string>{"clone","--filter=blob:none","--no-checkout",job.CloneUrl,temp};if(token is not null){args.InsertRange(0,["-c",$"http.extraHeader=Authorization: Bearer {token}"]);}var clone=await runner.Run("git",args,Path.GetTempPath(),TimeSpan.FromMinutes(3),stoppingToken);if(clone.ExitCode!=0)throw new InvalidOperationException("Repository clone failed.");var checkout=await runner.Run("git",["checkout",job.Ref],temp,TimeSpan.FromMinutes(2),stoppingToken);if(checkout.ExitCode!=0)throw new InvalidOperationException("Commit checkout failed.");var repoId=await EnsureRepository(job,temp,stoppingToken);await engine.Scan(repoId,temp,$"github:{job.Event}",job.Ref,stoppingToken);await Save(current with{Status="completed"},stoppingToken);}catch(Exception ex){logger.LogError(ex,"Webhook job {JobId} failed",job.Id);await Save(current with{Status="failed",Error=ex.Message},stoppingToken);}finally{try{if(Directory.Exists(temp))Directory.Delete(temp,true);}catch(IOException){}}}
    }
    private Task Save(WebhookJob job,CancellationToken ct)=>store.Mutate(s=>{s.WebhookJobs.RemoveAll(x=>x.Id==job.Id);s.WebhookJobs.Add(job);return 0;},ct);
    private Task<Guid> EnsureRepository(WebhookJob job,string path,CancellationToken ct)=>store.Mutate(s=>{var existing=s.Repositories.FirstOrDefault(x=>x.Name==job.Repository);if(existing is not null)return existing.Id;var record=new RepositoryRecord(Guid.NewGuid(),job.Repository,path,DateTimeOffset.UtcNow);s.Repositories.Add(record);return record.Id;},ct);
}
