using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace McpGuardian.Baselines;

public sealed class ConfigBaselineService
{
    private static readonly JsonSerializerOptions OutputOptions = new() { WriteIndented = true };

    public BaselineDocument Create(string configPath) =>
        new(1, Path.GetFileName(configPath), DateTimeOffset.UtcNow, ReadFingerprints(configPath));

    public void Save(BaselineDocument baseline, string outputPath)
    {
        EnsureParentDirectory(outputPath);
        File.WriteAllText(outputPath, JsonSerializer.Serialize(baseline, OutputOptions) + Environment.NewLine);
    }

    public BaselineVerification Verify(string configPath, string baselinePath)
    {
        var baseline = JsonSerializer.Deserialize<BaselineDocument>(File.ReadAllText(baselinePath))
            ?? throw new JsonException("Baseline file is empty.");
        if (baseline.Version != 1)
        {
            throw new InvalidDataException($"Unsupported baseline version: {baseline.Version}.");
        }

        var current = ReadFingerprints(configPath);
        var changes = new List<BaselineChange>();
        changes.AddRange(current.Keys.Except(baseline.Servers.Keys, StringComparer.Ordinal)
            .Select(server => new BaselineChange(server, BaselineChangeKind.Added)));
        changes.AddRange(baseline.Servers.Keys.Except(current.Keys, StringComparer.Ordinal)
            .Select(server => new BaselineChange(server, BaselineChangeKind.Removed)));

        foreach (var server in current.Keys.Intersect(baseline.Servers.Keys, StringComparer.Ordinal))
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(current[server]),
                    Convert.FromHexString(baseline.Servers[server])))
            {
                changes.Add(new BaselineChange(server, BaselineChangeKind.Modified));
            }
        }

        return new BaselineVerification(
            Path.GetFullPath(configPath),
            Path.GetFullPath(baselinePath),
            changes.OrderBy(change => change.Server, StringComparer.Ordinal).ToArray());
    }

    private static IReadOnlyDictionary<string, string> ReadFingerprints(string configPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(configPath), new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        });

        if (!TryGetServers(document.RootElement, out var servers))
        {
            throw new InvalidDataException("The configuration does not contain an mcpServers or servers object.");
        }

        return servers.EnumerateObject().ToDictionary(
            property => property.Name,
            property => ComputeHash(Canonicalize(property.Value)),
            StringComparer.Ordinal);
    }

    private static string Canonicalize(JsonElement element)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonical(element, writer);
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteCanonical(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(property.Value, writer);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonical(item, writer);
                }
                writer.WriteEndArray();
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static string ComputeHash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static bool TryGetServers(JsonElement root, out JsonElement servers)
    {
        if (root.TryGetProperty("mcpServers", out servers) && servers.ValueKind == JsonValueKind.Object)
        {
            return true;
        }

        return root.TryGetProperty("servers", out servers) && servers.ValueKind == JsonValueKind.Object;
    }

    private static void EnsureParentDirectory(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }
}
