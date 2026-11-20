using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardian.Models;

namespace McpGuardian.Cli;

public static class ReportWriter
{
    public static void WriteText(ScanReport report, TextWriter output)
        => WriteText(new[] { report }, output);

    public static void WriteText(IReadOnlyList<ScanReport> reports, TextWriter output)
    {
        for (var reportIndex = 0; reportIndex < reports.Count; reportIndex++)
        {
            var report = reports[reportIndex];
            if (reportIndex > 0)
            {
                output.WriteLine();
            }

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
    }

    public static void WriteJson(ScanReport report, TextWriter output)
        => WriteJson(new[] { report }, output);

    public static void WriteJson(IReadOnlyList<ScanReport> reports, TextWriter output)
    {
        var value = reports.Count == 1 ? (object)reports[0] : reports;
        output.WriteLine(JsonSerializer.Serialize(value, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        }));
    }

    public static void WriteSarif(IReadOnlyList<ScanReport> reports, TextWriter output)
    {
        var findings = reports.SelectMany(report => report.Findings.Select(finding => (report, finding))).ToArray();
        var rules = findings
            .Select(item => item.finding)
            .GroupBy(finding => finding.RuleId, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderBy(finding => finding.RuleId, StringComparer.Ordinal)
            .Select(finding => new
            {
                id = finding.RuleId,
                shortDescription = new { text = finding.Title },
                help = new { text = finding.Remediation }
            })
            .ToArray();

        var results = findings.Select(item => new
        {
            ruleId = item.finding.RuleId,
            level = ToSarifLevel(item.finding.Severity),
            message = new { text = $"{item.finding.Message} Server: {item.finding.Server}." },
            locations = new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = ToSarifUri(item.report.Target) }
                    }
                }
            }
        }).ToArray();

        var log = new Dictionary<string, object?>
        {
            ["version"] = "2.1.0",
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["runs"] = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "MCP Guardian",
                            informationUri = "https://github.com/hanzales/mcp-guardian",
                            rules
                        }
                    },
                    results
                }
            }
        };

        output.WriteLine(JsonSerializer.Serialize(log, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string ToSarifLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note"
    };

    private static string ToSarifUri(string target)
    {
        var relative = Path.GetRelativePath(Directory.GetCurrentDirectory(), target).Replace('\\', '/');
        return relative.StartsWith("../", StringComparison.Ordinal) ? Path.GetFileName(target) : relative;
    }
}
