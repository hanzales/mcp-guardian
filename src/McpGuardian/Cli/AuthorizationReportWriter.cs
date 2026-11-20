using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardian.Authorization;

namespace McpGuardian.Cli;

public static class AuthorizationReportWriter
{
    public static void WriteText(AuthorizationAuditReport report, TextWriter output)
    {
        output.WriteLine($"MCP Guardian authorization audit — {report.Source}");
        output.WriteLine($"Findings: {report.Findings.Count}");
        foreach (var finding in report.Findings)
        {
            output.WriteLine($"\n[{finding.Severity.ToString().ToUpperInvariant()}] {finding.RuleId} {finding.Title}");
            output.WriteLine($"  {finding.Message}\n  Fix: {finding.Remediation}");
        }
        if (report.Findings.Count == 0) output.WriteLine("No known authorization metadata or policy gaps detected.");
    }
    public static void WriteJson(AuthorizationAuditReport report, TextWriter output) => output.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } }));
}
