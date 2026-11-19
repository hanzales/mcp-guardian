using McpGuardian.Models;
using McpGuardian.Scanning;

var failures = new List<string>();
Run("detects vulnerable configuration", DetectsVulnerableConfiguration);
Run("accepts secure configuration", AcceptsSecureConfiguration);
Run("rejects malformed shape", RejectsMalformedShape);

if (failures.Count > 0)
{
    Console.Error.WriteLine($"{failures.Count} test(s) failed:");
    failures.ForEach(Console.Error.WriteLine);
    return 1;
}

Console.WriteLine("All 3 tests passed.");
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
    var report = Scan("{" + "\"servers\":{}}");
    Assert(report.Findings.Single().RuleId == "MCG001", "missing shape not detected");
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
