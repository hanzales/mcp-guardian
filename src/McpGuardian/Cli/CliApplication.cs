using System.Reflection;
using System.Text.Json;
using McpGuardian.Baselines;
using McpGuardian.Authorization;
using McpGuardian.Discovery;
using McpGuardian.Inspection;
using McpGuardian.Models;
using McpGuardian.Scanning;
using McpGuardian.Semantics;

namespace McpGuardian.Cli;

public static class CliApplication
{
    private const long MaxInspectionReportBytes = 10 * 1024 * 1024;
    public static int Run(string[] args, TextWriter output, TextWriter error)
        => RunAsync(args, output, error).GetAwaiter().GetResult();

    private static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
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
                "inspect" => await RunInspectAsync(args, output, error),
                "analyze" => RunAnalyze(args, output, error),
                "audit-auth" => RunAuthorizationAudit(args, output, error),
                "version" or "--version" => RunVersion(output),
                _ => UsageError($"Unknown command '{args[0]}'.", error)
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          JsonException or InvalidDataException or ArgumentException or
                                          HttpRequestException or TaskCanceledException)
        {
            error.WriteLine($"Command failed: {exception.Message}");
            return 2;
        }
    }

    private static int RunAuthorizationAudit(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length < 2 || args[1].StartsWith('-')) return UsageError("Expected: audit-auth <evidence.json>.", error);
        var format = ReadOption(args, "--format")?.ToLowerInvariant() ?? "text";
        if (format is not ("text" or "json")) return UsageError("--format must be text or json.", error);
        var input = JsonSerializer.Deserialize<AuthorizationAuditInput>(File.ReadAllText(args[1]), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? throw new InvalidDataException("Authorization evidence file is empty.");
        var report = new AuthorizationAuditor().Audit(input, args[1]);
        if (format == "json") AuthorizationReportWriter.WriteJson(report, output); else AuthorizationReportWriter.WriteText(report, output);
        var thresholdValue = ReadOption(args, "--fail-on");
        if (thresholdValue is null) return 0;
        if (!Enum.TryParse<Severity>(thresholdValue, true, out var threshold) || threshold == Severity.Info)
            return UsageError("--fail-on must be low, medium, high, or critical.", error);
        return report.HasAtLeast(threshold) ? 1 : 0;
    }

    private static int RunAnalyze(string[] args, TextWriter output, TextWriter error)
    {
        var paths = args.Skip(1).TakeWhile(argument => !argument.StartsWith('-')).ToArray();
        if (paths.Length == 0) return UsageError("Expected: analyze <inspection.json> [more reports...].", error);
        var format = ReadOption(args, "--format")?.ToLowerInvariant() ?? "text";
        if (format is not ("text" or "json")) return UsageError("--format must be text or json.", error);
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var reports = paths.Select(path => ReadInspectionReport(path, options))
            .ToArray();
        var report = new SemanticAnalyzer().Analyze(reports, paths.Select(Path.GetFullPath).ToArray());

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
            if (format == "json") SemanticReportWriter.WriteJson(report, destination);
            else SemanticReportWriter.WriteText(report, destination);
        }
        finally
        {
            fileWriter?.Dispose();
        }
        if (outputPath is not null) output.WriteLine($"Semantic report written to {Path.GetFullPath(outputPath)}");

        var thresholdValue = ReadOption(args, "--fail-on");
        if (thresholdValue is null) return 0;
        if (!Enum.TryParse<Severity>(thresholdValue, true, out var threshold) || threshold == Severity.Info)
            return UsageError("--fail-on must be low, medium, high, or critical.", error);
        return report.HasAtLeast(threshold) ? 1 : 0;
    }

    private static async Task<int> RunInspectAsync(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length < 2 || args[1].StartsWith('-'))
        {
            return UsageError("Expected: inspect <config> --server <name>.", error);
        }
        var serverName = ReadOption(args, "--server");
        if (string.IsNullOrWhiteSpace(serverName)) return UsageError("--server is required.", error);
        var format = ReadOption(args, "--format")?.ToLowerInvariant() ?? "text";
        if (format is not ("text" or "json")) return UsageError("--format must be text or json.", error);
        var timeoutSeconds = ReadPositiveInt(args, "--timeout", 10);
        var maxResponseBytes = ReadPositiveInt(args, "--max-response-bytes", 1_048_576);
        var saveBaseline = ReadOption(args, "--save-baseline");
        var verifyBaseline = ReadOption(args, "--baseline");
        if (saveBaseline is not null && verifyBaseline is not null)
            return UsageError("--save-baseline and --baseline cannot be used together.", error);

        var configPath = args[1];
        var server = ServerConfigReader.Read(configPath, serverName);
        if (server.IsStdio && !HasFlag(args, "--allow-process"))
        {
            return UsageError("Stdio inspection starts the configured process. Re-run with --allow-process to opt in.", error);
        }

        var limits = new InspectionLimits(TimeSpan.FromSeconds(timeoutSeconds), maxResponseBytes);
        await using IMcpTransport transport = server.IsStdio
            ? new StdioMcpTransport(server, limits)
            : new HttpMcpTransport(server, limits);
        var report = await new CapabilityInspector().InspectAsync(configPath, serverName, transport);

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
            if (format == "json") InspectionReportWriter.WriteJson(report, destination);
            else InspectionReportWriter.WriteText(report, destination);
        }
        finally
        {
            fileWriter?.Dispose();
        }
        if (outputPath is not null) output.WriteLine($"Inspection report written to {Path.GetFullPath(outputPath)}");

        var baselineService = new CapabilityBaselineService();
        if (saveBaseline is not null)
        {
            baselineService.Save(baselineService.Create(report), saveBaseline);
            output.WriteLine($"Capability baseline saved to {Path.GetFullPath(saveBaseline)}");
        }
        if (verifyBaseline is null) return 0;

        var verification = baselineService.Verify(report, verifyBaseline);
        if (verification.IsMatch)
        {
            output.WriteLine("Capability baseline verified: no tool-schema drift detected.");
            return 0;
        }
        output.WriteLine($"Tool-schema drift detected ({verification.Changes.Count} change(s)):");
        foreach (var change in verification.Changes) output.WriteLine($"- {change.Kind}: {change.Tool}");
        return 1;
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

    private static int ReadPositiveInt(IReadOnlyList<string> args, string name, int defaultValue)
    {
        var value = ReadOption(args, name);
        if (value is null) return defaultValue;
        if (!int.TryParse(value, out var parsed) || parsed <= 0)
            throw new ArgumentException($"Option {name} requires a positive integer.");
        return parsed;
    }

    private static InspectionReport ReadInspectionReport(string path, JsonSerializerOptions options)
    {
        var length = new FileInfo(path).Length;
        if (length > MaxInspectionReportBytes)
            throw new InvalidDataException($"Inspection report exceeds the {MaxInspectionReportBytes}-byte limit: {path}");
        return JsonSerializer.Deserialize<InspectionReport>(File.ReadAllText(path), options)
               ?? throw new InvalidDataException($"Inspection report is empty: {path}");
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
              mcp-guardian inspect <config> --server <name> [--allow-process]
                                  [--format text|json] [--output <file>]
                                  [--timeout <seconds>] [--max-response-bytes <bytes>]
                                  [--save-baseline <file> | --baseline <file>]
              mcp-guardian analyze <inspection.json> [more reports...]
                                  [--format text|json] [--output <file>]
                                  [--fail-on low|medium|high|critical]
              mcp-guardian audit-auth <evidence.json> [--format text|json]
                                  [--fail-on low|medium|high|critical]
              mcp-guardian version

            Exit codes:
              0  Command completed and the configured policy passed
              1  Findings reached --fail-on, or baseline/capability drift was detected
              2  Invalid usage, unreadable input, or malformed configuration
            """);
    }
}
