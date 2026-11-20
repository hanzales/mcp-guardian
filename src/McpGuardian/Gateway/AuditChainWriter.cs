using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace McpGuardian.Gateway;

public sealed class AuditChainWriter : IDisposable
{
    private readonly TextWriter writer;
    private string previousHash = new('0', 64);

    public AuditChainWriter(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        if (File.Exists(path) && File.ReadLines(path).LastOrDefault(line => !string.IsNullOrWhiteSpace(line)) is { } last)
        {
            using var document = JsonDocument.Parse(last);
            if (document.RootElement.TryGetProperty("hash", out var hash) && hash.GetString() is { Length: 64 } value)
                previousHash = value;
        }
        writer = new StreamWriter(path, append: true);
    }

    public void Write(string server, string tool, PolicyDecision decision, JsonElement arguments)
    {
        var argumentHash = Hash(arguments.GetRawText());
        var payload = JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow, server, tool, decision = decision.Allowed ? "allow" : decision.ApprovalRequired ? "approval-required" : "deny", decision.Reason, argumentHash, previousHash });
        var hash = Hash(payload);
        writer.WriteLine(JsonSerializer.Serialize(new { payload = JsonSerializer.Deserialize<JsonElement>(payload), hash }));
        writer.Flush();
        previousHash = hash;
    }

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public void Dispose() => writer.Dispose();
}
