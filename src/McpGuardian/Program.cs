using McpGuardian.Cli;
using McpGuardian.Models;
using McpGuardian.Scanning;

return Run(args);

static int Run(string[] args)
{
    if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
    {
        Console.WriteLine("mcp-guardian scan <config> [--format text|json] [--fail-on low|medium|high|critical]");
        return args.Length == 0 ? 2 : 0;
    }

    if (!string.Equals(args[0], "scan", StringComparison.OrdinalIgnoreCase) || args.Length < 2)
    {
        Console.Error.WriteLine("Expected: mcp-guardian scan <config>");
        return 2;
    }

    var path = args[1];
    var format = ReadOption(args, "--format") ?? "text";
    var failOnValue = ReadOption(args, "--fail-on");

    try
    {
        var report = new ConfigScanner().Scan(path);
        if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
        {
            ReportWriter.WriteJson(report, Console.Out);
        }
        else
        {
            ReportWriter.WriteText(report, Console.Out);
        }

        if (failOnValue is not null && Enum.TryParse<Severity>(failOnValue, true, out var threshold) &&
            report.HasAtLeast(threshold))
        {
            return 1;
        }

        return 0;
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
    {
        Console.Error.WriteLine($"Scan failed: {exception.Message}");
        return 2;
    }
}

static string? ReadOption(IReadOnlyList<string> args, string name)
{
    for (var index = 0; index < args.Count - 1; index++)
    {
        if (string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase))
        {
            return args[index + 1];
        }
    }

    return null;
}
