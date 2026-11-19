using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardian.Models;

namespace McpGuardian.Cli;

public static class ReportWriter
{
    public static void WriteText(ScanReport report, TextWriter output)
    {
        output.WriteLine($"MCP Guardian — {report.Target}");
        output.WriteLine($"Risk: {report.Risk.ToString().ToUpperInvariant()} | Score: {report.Score}/100 | Findings: {report.Findings.Count}");

        foreach (var finding in report.Findings.OrderByDescending(f => f.Severity))
        {
            output.WriteLine();
            output.WriteLine($"[{finding.Severity.ToString().ToUpperInvariant()}] {finding.RuleId} {finding.Title} ({finding.Server})");
            output.WriteLine($"  {finding.Message}");
            output.WriteLine($"  Fix: {finding.Remediation}");
        }

        if (report.Findings.Count == 0)
        {
            output.WriteLine("No known configuration risks detected.");
        }
    }

    public static void WriteJson(ScanReport report, TextWriter output)
    {
        output.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        }));
    }
}
