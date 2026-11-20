namespace McpGuardian.Discovery;

public sealed class ConfigDiscovery
{
    public IReadOnlyList<DiscoveredConfig> Discover(string homeDirectory, string currentDirectory)
    {
        var candidates = new List<DiscoveredConfig>
        {
            new("Project", Path.Combine(currentDirectory, ".mcp.json")),
            new("Claude Code", Path.Combine(currentDirectory, ".claude", "mcp.json")),
            new("Cursor", Path.Combine(currentDirectory, ".cursor", "mcp.json")),
            new("VS Code", Path.Combine(currentDirectory, ".vscode", "mcp.json")),
            new("Claude Code", Path.Combine(homeDirectory, ".claude.json")),
            new("Claude Code", Path.Combine(homeDirectory, ".claude", "mcp.json")),
            new("Cursor", Path.Combine(homeDirectory, ".cursor", "mcp.json")),
            new("VS Code", Path.Combine(homeDirectory, ".config", "Code", "User", "mcp.json")),
            new("Claude Desktop", Path.Combine(homeDirectory, "Library", "Application Support", "Claude", "claude_desktop_config.json")),
            new("Claude Desktop", Path.Combine(homeDirectory, ".config", "Claude", "claude_desktop_config.json")),
            new("Claude Desktop", Path.Combine(homeDirectory, "AppData", "Roaming", "Claude", "claude_desktop_config.json"))
        };

        return candidates
            .Where(candidate => File.Exists(candidate.Path))
            .DistinctBy(candidate => Path.GetFullPath(candidate.Path), StringComparer.OrdinalIgnoreCase)
            .OrderBy(candidate => candidate.Client, StringComparer.Ordinal)
            .ThenBy(candidate => candidate.Path, StringComparer.Ordinal)
            .ToArray();
    }
}
