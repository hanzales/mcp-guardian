using System.Text.Json;

namespace McpGuardian.Inspection;

public sealed record InspectionLimits(TimeSpan Timeout, int MaxResponseBytes)
{
    public static InspectionLimits Default { get; } = new(TimeSpan.FromSeconds(10), 1_048_576);
}

public sealed record ServerDefinition(
    string Name,
    string? Command,
    IReadOnlyList<string> Arguments,
    IReadOnlyDictionary<string, string> Environment,
    Uri? Url,
    IReadOnlyDictionary<string, string> Headers)
{
    public bool IsStdio => !string.IsNullOrWhiteSpace(Command);
}

public sealed record ServerIdentity(string Name, string? Version);

public sealed record CapabilityItem(
    string Name,
    string? Description,
    JsonElement Definition,
    string Fingerprint);

public sealed record CapabilityInventory(
    bool Tools,
    bool Resources,
    bool Prompts,
    bool Logging,
    IReadOnlyList<string> Experimental);

public sealed record InspectionReport(
    int Version,
    string Source,
    string Server,
    string Transport,
    DateTimeOffset InspectedAt,
    string ProtocolVersion,
    ServerIdentity ServerInfo,
    CapabilityInventory Capabilities,
    IReadOnlyList<CapabilityItem> Tools,
    IReadOnlyList<CapabilityItem> Resources,
    IReadOnlyList<CapabilityItem> Prompts,
    IReadOnlyList<string> Warnings);

public sealed record CapabilityBaseline(
    int Version,
    string Server,
    DateTimeOffset CreatedAt,
    IReadOnlyDictionary<string, string> Tools);

public enum CapabilityChangeKind
{
    Added,
    Removed,
    Modified
}

public sealed record CapabilityChange(string Tool, CapabilityChangeKind Kind);

public sealed record CapabilityVerification(IReadOnlyList<CapabilityChange> Changes)
{
    public bool IsMatch => Changes.Count == 0;
}
