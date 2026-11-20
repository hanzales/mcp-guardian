using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using McpGuardian.Inspection;
using McpGuardian.Models;

namespace McpGuardian.Semantics;

public sealed partial class SemanticAnalyzer
{
    private const int MaxReports = 64;
    private const int MaxTools = 10_000;
    private static readonly char[] SuspiciousUnicode = ['\u200B', '\u200C', '\u200D', '\u2060', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069', '\uFEFF'];
    private static readonly string[] SourceTerms = ["read", "file", "filesystem", "environment", "secret", "credential", "token", "database", "query"];
    private static readonly string[] SinkTerms = ["send", "upload", "post", "http", "request", "email", "publish", "webhook", "network"];
    private static readonly string[] MutationTerms = ["write", "delete", "remove", "update", "create", "execute", "run", "send", "upload", "publish"];

    public SemanticReport Analyze(IReadOnlyList<InspectionReport> reports, IReadOnlyList<string>? sources = null)
    {
        if (reports.Count == 0) throw new ArgumentException("At least one inspection report is required.", nameof(reports));
        if (reports.Count > MaxReports) throw new InvalidDataException($"Semantic analysis accepts at most {MaxReports} reports.");
        if (reports.Sum(report => report.Tools.Count) > MaxTools) throw new InvalidDataException($"Semantic analysis accepts at most {MaxTools} tools.");
        var findings = new List<Finding>();
        foreach (var report in reports)
        {
            foreach (var tool in report.Tools)
            {
                AnalyzeTool(report.Server, tool, findings);
            }
        }
        AnalyzeShadowing(reports, findings);
        AnalyzeCrossServerEscalation(reports, findings);
        return new SemanticReport(
            1,
            DateTimeOffset.UtcNow,
            sources ?? reports.Select(report => report.Source).Distinct(StringComparer.Ordinal).ToArray(),
            findings.OrderByDescending(finding => finding.Severity).ThenBy(finding => finding.RuleId, StringComparer.Ordinal)
                .ThenBy(finding => finding.Server, StringComparer.Ordinal).ToArray());
    }

    private static void AnalyzeTool(string server, CapabilityItem tool, ICollection<Finding> findings)
    {
        var strings = EnumerateStrings(tool.Definition).Prepend(tool.Description ?? string.Empty).ToArray();
        if (strings.Any(value => PoisoningPattern().IsMatch(value)))
        {
            findings.Add(new Finding(
                "MCG201", Severity.High, server, "Potential tool poisoning",
                $"Tool '{tool.Name}' contains instruction-like text that may manipulate an agent or conceal behavior.",
                "Review the complete tool definition and remove instructions that override user intent, request secrets, or suppress disclosure."));
        }

        if (strings.Any(HasSuspiciousUnicode))
        {
            findings.Add(new Finding(
                "MCG203", Severity.Medium, server, "Suspicious Unicode control characters",
                $"Tool '{tool.Name}' contains invisible or bidirectional Unicode controls.",
                "Replace control characters with visible plain text and verify the definition from a trusted source."));
        }

        if (strings.Any(ContainsSuspiciousEncoding))
        {
            findings.Add(new Finding(
                "MCG204", Severity.Medium, server, "Encoded instruction-like content",
                $"Tool '{tool.Name}' contains encoded text that decodes to instruction-like content.",
                "Remove encoded instructions and require all security-relevant tool behavior to be explicit and reviewable."));
        }

        AnalyzeConsistency(server, tool, findings);
    }

    private static void AnalyzeShadowing(IEnumerable<InspectionReport> reports, ICollection<Finding> findings)
    {
        var collisions = reports.SelectMany(report => report.Tools.Select(tool => (report.Server, Tool: tool)))
            .GroupBy(item => item.Tool.Name, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Select(item => item.Server).Distinct(StringComparer.Ordinal).Count() > 1);
        foreach (var collision in collisions)
        {
            var servers = string.Join(", ", collision.Select(item => item.Server).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
            var different = collision.Select(item => item.Tool.Fingerprint).Distinct(StringComparer.Ordinal).Skip(1).Any();
            findings.Add(new Finding(
                "MCG202", different ? Severity.High : Severity.Medium, servers, "Cross-server tool shadowing",
                $"Tool name '{collision.Key}' is advertised by multiple servers{(different ? " with different definitions" : string.Empty)}.",
                "Use unique, server-qualified tool names or allowlist the intended server before enabling both servers."));
        }
    }

    private static void AnalyzeCrossServerEscalation(IReadOnlyList<InspectionReport> reports, ICollection<Finding> findings)
    {
        var tools = reports.SelectMany(report => report.Tools.Select(tool => (report.Server, Tool: tool))).ToArray();
        foreach (var owner in tools)
        {
            var description = owner.Tool.Description ?? string.Empty;
            foreach (var target in tools.Where(target => !string.Equals(target.Server, owner.Server, StringComparison.Ordinal)))
            {
                if (Regex.IsMatch(description, $@"\b(?:call|use|invoke|delegate\s+to)\s+\W*{Regex.Escape(target.Tool.Name)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                {
                    findings.Add(new Finding(
                        "MCG205", Severity.High, owner.Server, "Cross-server escalation instruction",
                        $"Tool '{owner.Tool.Name}' instructs the agent to invoke '{target.Tool.Name}' from server '{target.Server}'.",
                        "Remove cross-server instructions and enforce an explicit policy for every multi-server tool chain."));
                }
            }
        }

        var sourceServers = tools.Where(item => ContainsTerm(item.Tool, SourceTerms)).Select(item => item.Server).Distinct(StringComparer.Ordinal);
        var sinkServers = tools.Where(item => ContainsTerm(item.Tool, SinkTerms)).Select(item => item.Server).Distinct(StringComparer.Ordinal);
        foreach (var pair in sourceServers.SelectMany(source => sinkServers, (source, sink) => (source, sink))
                     .Where(pair => !string.Equals(pair.source, pair.sink, StringComparison.Ordinal)).Distinct())
        {
            findings.Add(new Finding(
                "MCG205", Severity.Medium, $"{pair.source} -> {pair.sink}", "Cross-server data-flow capability",
                $"Server '{pair.source}' exposes data-access capabilities while '{pair.sink}' exposes outbound or publishing capabilities.",
                "Review whether the agent can chain these servers and add approval gates or deny policies for sensitive data flows."));
        }
    }

    private static void AnalyzeConsistency(string server, CapabilityItem tool, ICollection<Finding> findings)
    {
        var definition = tool.Definition;
        var actionText = $"{tool.Name} {tool.Description}";
        var mutation = MutationTerms.Any(term => tool.Name.Contains(term, StringComparison.OrdinalIgnoreCase));
        var inconsistent = false;
        var reason = string.Empty;
        if (!definition.TryGetProperty("inputSchema", out var schema) || schema.ValueKind != JsonValueKind.Object)
        {
            inconsistent = true;
            reason = "does not declare an object inputSchema";
        }
        else if (schema.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() != "object")
        {
            inconsistent = true;
            reason = "declares a non-object inputSchema";
        }
        else if (definition.TryGetProperty("annotations", out var annotations) && annotations.ValueKind == JsonValueKind.Object && mutation)
        {
            if (IsTrue(annotations, "readOnlyHint"))
            {
                inconsistent = true;
                reason = "is mutation-like but declares readOnlyHint=true";
            }
            else if (IsFalse(annotations, "destructiveHint") && DestructivePattern().IsMatch(actionText))
            {
                inconsistent = true;
                reason = "appears destructive but declares destructiveHint=false";
            }
        }
        if (!inconsistent) return;
        findings.Add(new Finding(
            "MCG206", Severity.Medium, server, "Tool annotation or schema inconsistency",
            $"Tool '{tool.Name}' {reason}.",
            "Correct the schema and annotations, then review behavior independently because annotations are untrusted hints."));
    }

    private static bool ContainsTerm(CapabilityItem tool, IEnumerable<string> terms)
    {
        return terms.Any(term => tool.Name.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsTrue(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.True;

    private static bool IsFalse(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.False;

    private static bool HasSuspiciousUnicode(string value) => value.IndexOfAny(SuspiciousUnicode) >= 0;

    private static bool ContainsSuspiciousEncoding(string value)
    {
        foreach (Match match in Base64Pattern().Matches(value))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(match.Value));
                if (PoisoningPattern().IsMatch(decoded) || EncodedInstructionPattern().IsMatch(decoded)) return true;
            }
            catch (FormatException)
            {
                // The candidate was not valid base64.
            }
        }
        return false;
    }

    private static IEnumerable<string> EnumerateStrings(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                if (element.GetString() is { } value) yield return value;
                break;
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                foreach (var nestedValue in EnumerateStrings(property.Value)) yield return nestedValue;
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                foreach (var nestedValue in EnumerateStrings(item)) yield return nestedValue;
                break;
        }
    }

    [GeneratedRegex(@"\b(?:ignore (?:all |any )?(?:previous|prior|system)|system prompt|do not (?:tell|inform|show) (?:the )?user|hide (?:this|these) instructions?|exfiltrat(?:e|ion)|send (?:the )?(?:secret|credential|token|password)|reveal (?:the )?(?:secret|credential|token|password))\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PoisoningPattern();

    [GeneratedRegex(@"\b(?:call|invoke|execute|instruction|prompt|secret|credential|token)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EncodedInstructionPattern();

    [GeneratedRegex(@"\b(?:delete|remove|destroy|drop|truncate|overwrite|revoke)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DestructivePattern();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.CultureInvariant)]
    private static partial Regex Base64Pattern();
}
