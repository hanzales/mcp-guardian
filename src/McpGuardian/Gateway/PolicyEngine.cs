using System.Text.Json;

namespace McpGuardian.Gateway;

public sealed class PolicyEngine
{
    private readonly GatewayPolicy policy;
    private readonly Queue<DateTimeOffset> requests = new();

    public PolicyEngine(GatewayPolicy policy)
    {
        this.policy = policy;
        if (policy.Version != 1) throw new InvalidDataException($"Unsupported gateway policy version: {policy.Version}.");
        if (policy.Limits is { RequestsPerMinute: <= 0 } or { MaxRequestBytes: <= 0 } or { MaxResponseBytes: <= 0 } or { TimeoutSeconds: <= 0 })
            throw new InvalidDataException("Gateway limits must be positive.");
    }

    public PolicyDecision Evaluate(string server, string tool, JsonElement arguments, DateTimeOffset now)
    {
        while (requests.TryPeek(out var oldest) && now - oldest >= TimeSpan.FromMinutes(1)) requests.Dequeue();
        if (requests.Count >= policy.Limits.RequestsPerMinute) return new(false, false, "rate limit exceeded");
        requests.Enqueue(now);
        if (!policy.Servers.TryGetValue(server, out var serverPolicy)) return Action(policy.DefaultAction, "server is not explicitly configured");
        var action = serverPolicy.Tools.TryGetValue(tool, out var configured) ? configured : policy.DefaultAction;
        var decision = Action(action, $"tool policy is {action}");
        if (!decision.Allowed) return decision;
        foreach (var value in Strings(arguments))
        {
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Host.Length > 0 &&
                !serverPolicy.AllowedNetworkHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
                return new(false, false, $"network destination '{uri.Host}' is not allowlisted");
            if (Path.IsPathRooted(value))
            {
                var full = Path.GetFullPath(value);
                if (!serverPolicy.AllowedPathRoots.Any(root => IsWithin(Path.GetFullPath(root), full)))
                    return new(false, false, "filesystem path is outside allowlisted roots");
            }
        }
        return decision;
    }

    private static PolicyDecision Action(string action, string reason) => action.ToLowerInvariant() switch
    {
        "allow" => new(true, false, reason),
        "approval" => new(false, true, "explicit user approval is required"),
        "deny" => new(false, false, reason),
        _ => throw new InvalidDataException($"Unknown gateway action: {action}.")
    };

    private static bool IsWithin(string root, string candidate)
    {
        var relative = Path.GetRelativePath(root, candidate);
        return relative == "." || (!relative.StartsWith("..", StringComparison.Ordinal) && !Path.IsPathRooted(relative));
    }

    private static IEnumerable<string> Strings(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String && element.GetString() is { } text) yield return text;
        if (element.ValueKind == JsonValueKind.Object)
            foreach (var property in element.EnumerateObject()) foreach (var value in Strings(property.Value)) yield return value;
        if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) foreach (var value in Strings(item)) yield return value;
    }
}
