using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace McpGuardian.Inspection;

public sealed class CapabilityInspector
{
    private const string RequestedProtocolVersion = "2025-11-25";

    public async Task<InspectionReport> InspectAsync(
        string source,
        string serverName,
        IMcpTransport transport,
        CancellationToken cancellationToken = default)
    {
        using var initialized = await transport.SendRequestAsync("initialize", new
        {
            protocolVersion = RequestedProtocolVersion,
            capabilities = new { },
            clientInfo = new { name = "mcp-guardian", version = "0.3.0" }
        }, cancellationToken);
        var result = GetResult(initialized.RootElement, "initialize");
        var protocolVersion = GetString(result, "protocolVersion") ?? throw new InvalidDataException("Initialize response omitted protocolVersion.");
        var serverInfo = ReadServerInfo(result);
        var capabilities = ReadCapabilities(result);
        await transport.SendNotificationAsync("notifications/initialized", null, cancellationToken);

        var warnings = new List<string>();
        var tools = capabilities.Tools
            ? await ReadItemsAsync(transport, "tools/list", "tools", warnings, cancellationToken)
            : Array.Empty<CapabilityItem>();
        var resources = capabilities.Resources
            ? await ReadItemsAsync(transport, "resources/list", "resources", warnings, cancellationToken)
            : Array.Empty<CapabilityItem>();
        var prompts = capabilities.Prompts
            ? await ReadItemsAsync(transport, "prompts/list", "prompts", warnings, cancellationToken)
            : Array.Empty<CapabilityItem>();

        return new InspectionReport(
            1, Path.GetFullPath(source), serverName, transport.Name, DateTimeOffset.UtcNow,
            protocolVersion, serverInfo, capabilities, tools, resources, prompts, warnings);
    }

    private static async Task<IReadOnlyList<CapabilityItem>> ReadItemsAsync(
        IMcpTransport transport,
        string method,
        string property,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var items = new List<CapabilityItem>();
        string? cursor = null;
        for (var page = 0; page < 100; page++)
        {
            using var response = await transport.SendRequestAsync(method, cursor is null ? new { } : new { cursor }, cancellationToken);
            if (response.RootElement.TryGetProperty("error", out var error))
            {
                warnings.Add($"{method} failed: {ReadError(error)}");
                break;
            }

            var result = GetResult(response.RootElement, method);
            if (result.TryGetProperty(property, out var values) && values.ValueKind == JsonValueKind.Array)
            {
                foreach (var value in values.EnumerateArray())
                {
                    var name = GetString(value, "name") ?? "<unnamed>";
                    var description = GetString(value, "description");
                    var definition = value.Clone();
                    items.Add(new CapabilityItem(name, description, definition, Fingerprint(value)));
                }
            }

            cursor = GetString(result, "nextCursor");
            if (string.IsNullOrEmpty(cursor)) break;
            if (page == 99) throw new InvalidDataException($"{method} exceeded the 100-page safety limit.");
        }

        return items.OrderBy(item => item.Name, StringComparer.Ordinal).ToArray();
    }

    private static JsonElement GetResult(JsonElement response, string method)
    {
        if (response.TryGetProperty("error", out var error))
        {
            throw new InvalidDataException($"MCP {method} failed: {ReadError(error)}");
        }
        if (!response.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"MCP {method} response omitted its result object.");
        }
        return result;
    }

    private static string ReadError(JsonElement error)
    {
        var code = error.TryGetProperty("code", out var codeValue) ? codeValue.ToString() : "unknown";
        var message = GetString(error, "message") ?? "Unknown MCP error";
        return $"{code} {message}";
    }

    private static ServerIdentity ReadServerInfo(JsonElement result)
    {
        if (!result.TryGetProperty("serverInfo", out var info) || info.ValueKind != JsonValueKind.Object)
        {
            return new ServerIdentity("unknown", null);
        }
        return new ServerIdentity(GetString(info, "name") ?? "unknown", GetString(info, "version"));
    }

    private static CapabilityInventory ReadCapabilities(JsonElement result)
    {
        if (!result.TryGetProperty("capabilities", out var capabilities) || capabilities.ValueKind != JsonValueKind.Object)
        {
            return new CapabilityInventory(false, false, false, false, Array.Empty<string>());
        }
        var experimental = capabilities.TryGetProperty("experimental", out var value) && value.ValueKind == JsonValueKind.Object
            ? value.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray()
            : Array.Empty<string>();
        return new CapabilityInventory(
            capabilities.TryGetProperty("tools", out _),
            capabilities.TryGetProperty("resources", out _),
            capabilities.TryGetProperty("prompts", out _),
            capabilities.TryGetProperty("logging", out _),
            experimental);
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string Fingerprint(JsonElement value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) WriteCanonical(value, writer);
        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }

    private static void WriteCanonical(JsonElement value, Utf8JsonWriter writer)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in value.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(property.Value, writer);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray()) WriteCanonical(item, writer);
                writer.WriteEndArray();
                break;
            default:
                value.WriteTo(writer);
                break;
        }
    }
}
