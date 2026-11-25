using System.Net;
using McpGuardian.Models;

namespace McpGuardian.Cli;

internal static class HtmlReportWriter
{
    public static void Write(IReadOnlyList<ScanReport> reports, TextWriter output)
    {
        var findings = reports.SelectMany(report => report.Findings.Select(finding => (report, finding))).ToArray();
        output.WriteLine("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>MCP Guardian report</title>");
        output.WriteLine("<style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}h1{color:#0b5cad}.summary{display:flex;gap:1rem;flex-wrap:wrap}.card{padding:.75rem 1rem;border:1px solid #d9e2ec;border-radius:8px}.critical{color:#b42318}.high{color:#c4320a}.medium{color:#a15c00}.low{color:#176b3a}table{border-collapse:collapse;width:100%;margin-top:1rem}th,td{text-align:left;padding:.65rem;border-bottom:1px solid #e5e7eb;vertical-align:top}th{background:#f4f7fa}code{font-family:ui-monospace,monospace}</style></head><body>");
        output.WriteLine("<h1>MCP Guardian security report</h1>");
        output.WriteLine($"<p>Generated {Encode(DateTimeOffset.UtcNow.ToString("u"))}. Queries scanned: {reports.Count}.</p>");
        output.WriteLine("<div class=\"summary\">");
        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            var count = findings.Count(item => item.finding.Severity == severity);
            output.WriteLine($"<div class=\"card {severity.ToString().ToLowerInvariant()}\"><strong>{severity}</strong><br>{count} finding(s)</div>");
        }
        output.WriteLine("</div>");
        if (findings.Length == 0)
        {
            output.WriteLine("<p class=\"card\">No known configuration risks detected.</p>");
        }
        else
        {
            output.WriteLine("<table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>");
            foreach (var item in findings.OrderByDescending(item => item.finding.Severity))
            {
                var finding = item.finding;
                output.WriteLine($"<tr><td class=\"{finding.Severity.ToString().ToLowerInvariant()}\"><strong>{Encode(finding.Severity.ToString().ToUpperInvariant())}</strong></td><td><code>{Encode(finding.RuleId)}</code></td><td>{Encode(item.report.Target)}<br>{Encode(finding.Server)}</td><td><strong>{Encode(finding.Title)}</strong><br>{Encode(finding.Message)}</td><td>{Encode(finding.Remediation)}</td></tr>");
            }
            output.WriteLine("</tbody></table>");
        }
        output.WriteLine("</body></html>");
    }

    private static string Encode(string value) => WebUtility.HtmlEncode(value);
}
