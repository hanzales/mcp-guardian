using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardian.Semantics;

namespace McpGuardian.Cli;

public static class SemanticReportWriter
{
    public static void WriteText(SemanticReport report, TextWriter output)
    {
        output.WriteLine($"MCP Guardian semantic analysis — {report.Sources.Count} inspection report(s)");
        output.WriteLine($"Findings: {report.Findings.Count}");
        foreach (var finding in report.Findings)
        {
            output.WriteLine();
            output.WriteLine($"[{finding.Severity.ToString().ToUpperInvariant()}] {finding.RuleId} {finding.Title} ({finding.Server})");
            output.WriteLine($"  {finding.Message}");
            output.WriteLine($"  Fix: {finding.Remediation}");
        }
        if (report.Findings.Count == 0) output.WriteLine("No known semantic attack-surface indicators detected.");
    }

    public static void WriteJson(SemanticReport report, TextWriter output) =>
        output.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        }));
}
