using System.Text.Json;

namespace McpGuardian.Inspection;

public static class ServerConfigReader
{
    public static ServerDefinition Read(string configPath, string serverName)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(configPath), new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        });

        if (!TryGetServers(document.RootElement, out var servers) ||
            !servers.TryGetProperty(serverName, out var server) || server.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"MCP server '{serverName}' was not found in the configuration.");
        }

        var command = ReadString(server, "command");
        var urlValue = ReadString(server, "url");
        var url = Uri.TryCreate(urlValue, UriKind.Absolute, out var parsedUrl) ? parsedUrl : null;
        if (string.IsNullOrWhiteSpace(command) == (url is null))
        {
            throw new InvalidDataException($"MCP server '{serverName}' must define exactly one of command or url.");
        }

        return new ServerDefinition(
            serverName,
            command,
            ReadArray(server, "args"),
            ReadObject(server, "env"),
            url,
            ReadObject(server, "headers"));
    }

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static IReadOnlyList<string> ReadArray(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString()!).ToArray()
            : Array.Empty<string>();

    private static IReadOnlyDictionary<string, string> ReadObject(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Object
            ? value.EnumerateObject()
                .Where(property => property.Value.ValueKind == JsonValueKind.String)
                .ToDictionary(property => property.Name, property => property.Value.GetString()!, StringComparer.Ordinal)
            : new Dictionary<string, string>(StringComparer.Ordinal);

    private static bool TryGetServers(JsonElement root, out JsonElement servers)
    {
        if (root.TryGetProperty("mcpServers", out servers) && servers.ValueKind == JsonValueKind.Object)
        {
            return true;
        }

        return root.TryGetProperty("servers", out servers) && servers.ValueKind == JsonValueKind.Object;
    }
}
