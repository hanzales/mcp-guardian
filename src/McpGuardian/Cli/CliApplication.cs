using System.Reflection;
using System.Text.Json;
using McpGuardian.Baselines;
using McpGuardian.Discovery;
using McpGuardian.Models;
using McpGuardian.Scanning;

namespace McpGuardian.Cli;

public static class CliApplication
{
    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length == 0 || HasFlag(args, "--help", "-h"))
        {
            WriteHelp(output);
            return args.Length == 0 ? 2 : 0;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "scan" => RunScan(args, output, error),
                "discover" => RunDiscover(args, output),
                "baseline" => RunBaseline(args, output, error),
                "version" or "--version" => RunVersion(output),
                _ => UsageError($"Unknown command '{args[0]}'.", error)
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          JsonException or InvalidDataException or ArgumentException)
        {
            error.WriteLine($"Command failed: {exception.Message}");
            return 2;
        }
    }

    private static int RunScan(string[] args, TextWriter output, TextWriter error)
    {
        var format = ReadOption(args, "--format")?.ToLowerInvariant() ?? "text";
        if (format is not ("text" or "json" or "sarif"))
        {
            return UsageError("--format must be text, json, or sarif.", error);
        }

        var targets = HasFlag(args, "--all")
            ? DiscoverConfigs().Select(config => config.Path).ToArray()
            : ReadScanTarget(args) is { } target ? new[] { target } : Array.Empty<string>();

        if (targets.Length == 0)
        {
            return UsageError(HasFlag(args, "--all")
                ? "No supported MCP configuration files were discovered."
                : "Expected a config path or --all.", error);
        }

        var reports = targets.Select(path => new ConfigScanner().Scan(path)).ToArray();
        var outputPath = ReadOption(args, "--output");
        TextWriter destination = output;
        StreamWriter? fileWriter = null;
        if (outputPath is not null)
        {
            EnsureParentDirectory(outputPath);
            fileWriter = new StreamWriter(outputPath, false);
            destination = fileWriter;
        }

        try
        {
            switch (format)
            {
                case "json":
                    ReportWriter.WriteJson(reports, destination);
                    break;
                case "sarif":
                    ReportWriter.WriteSarif(reports, destination);
                    break;
                default:
                    ReportWriter.WriteText(reports, destination);
                    break;
            }
        }
        finally
        {
            fileWriter?.Dispose();
        }

        if (outputPath is not null)
        {
            output.WriteLine($"Report written to {Path.GetFullPath(outputPath)}");
        }

        var thresholdValue = ReadOption(args, "--fail-on");
        if (thresholdValue is null)
        {
            return 0;
        }

        if (!Enum.TryParse<Severity>(thresholdValue, true, out var threshold) || threshold == Severity.Info)
        {
            return UsageError("--fail-on must be low, medium, high, or critical.", error);
        }

        return reports.Any(report => report.HasAtLeast(threshold)) ? 1 : 0;
    }

    private static int RunDiscover(string[] args, TextWriter output)
    {
        var configs = DiscoverConfigs();
        if (HasFlag(args, "--json"))
        {
            output.WriteLine(JsonSerializer.Serialize(configs, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }

        if (configs.Count == 0)
        {
            output.WriteLine("No supported MCP configuration files found.");
            return 0;
        }

        output.WriteLine($"Discovered {configs.Count} MCP configuration file(s):");
        foreach (var config in configs)
        {
            output.WriteLine($"- {config.Client}: {config.Path}");
        }

        return 0;
    }

    private static int RunBaseline(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length < 3)
        {
            return UsageError("Expected: baseline create|verify <config>.", error);
        }

        var service = new ConfigBaselineService();
        var configPath = args[2];
        var baselinePath = ReadOption(args, "--output") ?? ReadOption(args, "--baseline") ??
                           Path.Combine(Path.GetDirectoryName(Path.GetFullPath(configPath))!, ".mcp-guardian.baseline.json");

        if (string.Equals(args[1], "create", StringComparison.OrdinalIgnoreCase))
        {
            var baseline = service.Create(configPath);
            service.Save(baseline, baselinePath);
            output.WriteLine($"Trusted baseline created for {baseline.Servers.Count} server(s): {Path.GetFullPath(baselinePath)}");
            return 0;
        }

        if (string.Equals(args[1], "verify", StringComparison.OrdinalIgnoreCase))
        {
            var verification = service.Verify(configPath, baselinePath);
            if (verification.IsMatch)
            {
                output.WriteLine("Baseline verified: no MCP server configuration drift detected.");
                return 0;
            }

            output.WriteLine($"Baseline drift detected ({verification.Changes.Count} change(s)):");
            foreach (var change in verification.Changes)
            {
                output.WriteLine($"- {change.Kind}: {change.Server}");
            }

            return 1;
        }

        return UsageError("Baseline action must be create or verify.", error);
    }

    private static int RunVersion(TextWriter output)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown";
        output.WriteLine($"mcp-guardian {version}");
        return 0;
    }

    private static IReadOnlyList<DiscoveredConfig> DiscoverConfigs() =>
        new ConfigDiscovery().Discover(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Directory.GetCurrentDirectory());

    private static string? ReadScanTarget(IReadOnlyList<string> args) =>
        args.Count > 1 && !args[1].StartsWith('-') ? args[1] : null;

    private static string? ReadOption(IReadOnlyList<string> args, string name)
    {
        for (var index = 0; index < args.Count; index++)
        {
            if (!string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (index == args.Count - 1 || args[index + 1].StartsWith('-'))
            {
                throw new ArgumentException($"Option {name} requires a value.");
            }

            return args[index + 1];
        }

        return null;
    }

    private static bool HasFlag(IEnumerable<string> args, params string[] names) =>
        args.Any(arg => names.Contains(arg, StringComparer.OrdinalIgnoreCase));

    private static int UsageError(string message, TextWriter error)
    {
        error.WriteLine(message);
        error.WriteLine("Run 'mcp-guardian --help' for usage.");
        return 2;
    }

    private static void EnsureParentDirectory(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static void WriteHelp(TextWriter output)
    {
        output.WriteLine("""
            MCP Guardian — security scanner for Model Context Protocol configurations

            Usage:
              mcp-guardian discover [--json]
              mcp-guardian scan <config> [--format text|json|sarif] [--output <file>]
                                         [--fail-on low|medium|high|critical]
              mcp-guardian scan --all [scan options]
              mcp-guardian baseline create <config> [--output <file>]
              mcp-guardian baseline verify <config> [--baseline <file>]
              mcp-guardian version

            Exit codes:
              0  Command completed and the configured policy passed
              1  Findings reached --fail-on, or baseline drift was detected
              2  Invalid usage, unreadable input, or malformed configuration
            """);
    }
}
