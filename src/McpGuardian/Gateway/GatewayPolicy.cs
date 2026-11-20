namespace McpGuardian.Gateway;

public sealed record GatewayPolicy(
    int Version,
    string DefaultAction,
    IReadOnlyDictionary<string, ServerPolicy> Servers,
    GatewayLimits Limits);

public sealed record ServerPolicy(
    IReadOnlyDictionary<string, string> Tools,
    IReadOnlyList<string> AllowedPathRoots,
    IReadOnlyList<string> AllowedNetworkHosts);

public sealed record GatewayLimits(int RequestsPerMinute, int MaxRequestBytes, int MaxResponseBytes, int TimeoutSeconds);

public sealed record PolicyDecision(bool Allowed, bool ApprovalRequired, string Reason);
