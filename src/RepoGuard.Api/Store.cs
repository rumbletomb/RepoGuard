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
        if (!File.Exists(_path)) return new([], [], new Policy());
        var json = await File.ReadAllTextAsync(_path, ct);
        return JsonSerializer.Deserialize<DataState>(json, Json) ?? new([], [], new Policy());
    }
}
