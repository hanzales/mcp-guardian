using System.Text.Json;

namespace McpGuardian.Cli;

internal sealed class ScanConfiguration
{
    public string? FailOn { get; set; }
    public string? Format { get; set; }
    public string? Output { get; set; }
    public List<string> IgnoredRules { get; set; } = [];

    public static ScanConfiguration Load(string? explicitPath)
    {
        var path = explicitPath;
        if (path is null)
        {
            var candidates = new[] { ".mcp-guardian.json", Path.Combine(".mcp-guardian", "config.json") };
            path = candidates.FirstOrDefault(File.Exists);
        }

        if (path is null) return new ScanConfiguration();
        var configuration = JsonSerializer.Deserialize<ScanConfiguration>(File.ReadAllText(path), new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? throw new InvalidDataException($"Scan configuration is empty: {path}");
        configuration.IgnoredRules ??= [];
        return configuration;
    }
}
