using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RepoGuard.Api.GitHub;

public sealed class GitHubInstallationTokenProvider(HttpClient http,IConfiguration configuration)
{
    public async Task<string?> Get(long installationId,CancellationToken ct)
    {
        var appId=configuration["GitHub:AppId"];var key=configuration["GitHub:PrivateKeyPem"]?.Replace("\\n","\n");if(string.IsNullOrWhiteSpace(appId)||string.IsNullOrWhiteSpace(key))return null;
        using var rsa=RSA.Create();rsa.ImportFromPem(key);var now=DateTimeOffset.UtcNow;var header=Base64Url(JsonSerializer.SerializeToUtf8Bytes(new{alg="RS256",typ="JWT"}));var payload=Base64Url(JsonSerializer.SerializeToUtf8Bytes(new{iat=now.AddSeconds(-30).ToUnixTimeSeconds(),exp=now.AddMinutes(9).ToUnixTimeSeconds(),iss=appId}));var input=$"{header}.{payload}";var sig=Base64Url(rsa.SignData(Encoding.ASCII.GetBytes(input),HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1));
        using var request=new HttpRequestMessage(HttpMethod.Post,$"app/installations/{installationId}/access_tokens");request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",$"{input}.{sig}");request.Headers.Accept.Add(new("application/vnd.github+json"));request.Headers.Add("X-GitHub-Api-Version","2022-11-28");using var response=await http.SendAsync(request,ct);response.EnsureSuccessStatusCode();using var doc=JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));return doc.RootElement.GetProperty("token").GetString();
    }
    private static string Base64Url(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
}
