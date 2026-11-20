using McpGuardian.Baselines;
using McpGuardian.Cli;
using McpGuardian.Discovery;
using McpGuardian.Models;
using McpGuardian.Scanning;

var failures = new List<string>();
Run("detects vulnerable configuration", DetectsVulnerableConfiguration);
Run("accepts secure configuration", AcceptsSecureConfiguration);
Run("rejects malformed shape", RejectsMalformedShape);
Run("accepts VS Code servers shape", AcceptsVsCodeServersShape);
Run("discovers supported client configuration", DiscoversSupportedClientConfiguration);
Run("creates stable canonical baseline", CreatesStableCanonicalBaseline);
Run("detects baseline drift", DetectsBaselineDrift);
Run("writes valid SARIF", WritesValidSarif);
Run("CLI honors fail-on threshold", CliHonorsFailOnThreshold);

if (failures.Count > 0)
{
    Console.Error.WriteLine($"{failures.Count} test(s) failed:");
    failures.ForEach(Console.Error.WriteLine);
    return 1;
}

Console.WriteLine("All 9 tests passed.");
return 0;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception exception)
    {
        failures.Add($"FAIL {name}: {exception.Message}");
    }
}

void DetectsVulnerableConfiguration()
{
    var report = Scan("""
        {"mcpServers":{"bad":{"command":"npx","args":["untrusted-package","/"],"env":{"API_TOKEN":"literal-secret-value"}}}}
        """);
    Assert(report.Findings.Any(f => f.RuleId == "MCG102"), "unpinned package not detected");
    Assert(report.Findings.Any(f => f.RuleId == "MCG103"), "broad path not detected");
    Assert(report.Findings.Any(f => f.RuleId == "MCG105"), "literal secret not detected");
    Assert(report.Risk >= Severity.High, "risk should be high or critical");
}

void AcceptsSecureConfiguration()
{
    var report = Scan("""
        {"mcpServers":{"safe":{"command":"npx","args":["@example/server@1.2.3","/workspace/project"],"env":{"API_TOKEN":"${API_TOKEN}"}}}}
        """);
    Assert(report.Findings.Count == 0, "secure configuration produced findings");
}

void RejectsMalformedShape()
{
    var report = Scan("{" + "\"unrelated\":{}}");
    Assert(report.Findings.Single().RuleId == "MCG001", "missing shape not detected");
}

void AcceptsVsCodeServersShape()
{
    var report = Scan("""
        {"servers":{"safe":{"type":"stdio","command":"server","args":["--safe"]}}}
        """);
    Assert(report.Findings.Count == 0, "VS Code servers shape produced findings");
}

void DiscoversSupportedClientConfiguration()
{
    WithTempDirectory(directory =>
    {
        var cursorDirectory = Path.Combine(directory, ".cursor");
        Directory.CreateDirectory(cursorDirectory);
        File.WriteAllText(Path.Combine(cursorDirectory, "mcp.json"), "{\"mcpServers\":{}}");

        var discovered = new ConfigDiscovery().Discover(Path.Combine(directory, "home"), directory);
        Assert(discovered.Count == 1, "expected one discovered config");
        Assert(discovered[0].Client == "Cursor", "expected Cursor config");
    });
}

void CreatesStableCanonicalBaseline()
{
    WithTempDirectory(directory =>
    {
        var first = Path.Combine(directory, "first.json");
        var second = Path.Combine(directory, "second.json");
        File.WriteAllText(first, "{\"mcpServers\":{\"safe\":{\"command\":\"npx\",\"args\":[\"pkg@1.0.0\"]}}}");
        File.WriteAllText(second, "{\"mcpServers\":{\"safe\":{\"args\":[\"pkg@1.0.0\"],\"command\":\"npx\"}}}");

        var service = new ConfigBaselineService();
        var firstHash = service.Create(first).Servers["safe"];
        var secondHash = service.Create(second).Servers["safe"];
        Assert(firstHash == secondHash, "property ordering changed the fingerprint");
    });
}

void DetectsBaselineDrift()
{
    WithTempDirectory(directory =>
    {
        var config = Path.Combine(directory, "mcp.json");
        var baselinePath = Path.Combine(directory, "baseline.json");
        File.WriteAllText(config, "{\"mcpServers\":{\"safe\":{\"command\":\"server\"}}}");

        var service = new ConfigBaselineService();
        service.Save(service.Create(config), baselinePath);
        File.WriteAllText(config, "{\"mcpServers\":{\"safe\":{\"command\":\"changed\"},\"new\":{\"url\":\"https://example.com\"}}}");

        var verification = service.Verify(config, baselinePath);
        Assert(verification.Changes.Any(change => change.Server == "safe" && change.Kind == BaselineChangeKind.Modified),
            "modified server not detected");
        Assert(verification.Changes.Any(change => change.Server == "new" && change.Kind == BaselineChangeKind.Added),
            "added server not detected");
    });
}

void WritesValidSarif()
{
    var report = Scan("""
        {"mcpServers":{"bad":{"command":"bash","args":["-c","echo unsafe"]}}}
        """);
    using var writer = new StringWriter();
    ReportWriter.WriteSarif(new[] { report }, writer);
    using var document = System.Text.Json.JsonDocument.Parse(writer.ToString());
    Assert(document.RootElement.GetProperty("version").GetString() == "2.1.0", "invalid SARIF version");
    Assert(document.RootElement.GetProperty("runs")[0].GetProperty("results").GetArrayLength() > 0,
        "SARIF results are empty");
}

void CliHonorsFailOnThreshold()
{
    WithTempDirectory(directory =>
    {
        var config = Path.Combine(directory, "mcp.json");
        File.WriteAllText(config, "{\"mcpServers\":{\"bad\":{\"command\":\"bash\"}}}");
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = CliApplication.Run(new[] { "scan", config, "--fail-on", "high" }, output, error);
        Assert(exitCode == 1, "CLI did not fail on a critical finding");
    });
}

ScanReport Scan(string json)
{
    var path = Path.GetTempFileName();
    try
    {
        File.WriteAllText(path, json);
        return new ConfigScanner().Scan(path);
    }
    finally
    {
        File.Delete(path);
    }
}

void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

void WithTempDirectory(Action<string> action)
{
    var directory = Path.Combine(Path.GetTempPath(), $"mcp-guardian-tests-{Guid.NewGuid():N}");
    Directory.CreateDirectory(directory);
    try
    {
        action(directory);
    }
    finally
    {
        Directory.Delete(directory, true);
    }
}
