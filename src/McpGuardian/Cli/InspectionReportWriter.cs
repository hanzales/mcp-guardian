using System.Text.Json;
using System.Text.Json.Serialization;
using McpGuardian.Inspection;

namespace McpGuardian.Cli;

public static class InspectionReportWriter
{
    public static void WriteText(InspectionReport report, TextWriter output)
    {
        output.WriteLine($"MCP Guardian capability inspection — {report.Server}");
        output.WriteLine($"Transport: {report.Transport} | Protocol: {report.ProtocolVersion} | Server: {report.ServerInfo.Name} {report.ServerInfo.Version}".TrimEnd());
        output.WriteLine($"Capabilities: tools={report.Capabilities.Tools}, resources={report.Capabilities.Resources}, prompts={report.Capabilities.Prompts}, logging={report.Capabilities.Logging}");
        WriteItems("Tools", report.Tools, output);
        WriteItems("Resources", report.Resources, output);
        WriteItems("Prompts", report.Prompts, output);
        foreach (var warning in report.Warnings) output.WriteLine($"Warning: {warning}");
    }

    public static void WriteJson(InspectionReport report, TextWriter output) =>
        output.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        }));

    private static void WriteItems(string title, IReadOnlyList<CapabilityItem> items, TextWriter output)
    {
        output.WriteLine($"{title} ({items.Count}):");
        foreach (var item in items) output.WriteLine($"- {item.Name} [{item.Fingerprint[..12]}]");
    }
}
