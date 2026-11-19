namespace McpGuardian.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public sealed record Finding(
    string RuleId,
    Severity Severity,
    string Server,
    string Title,
    string Message,
    string Remediation);

public sealed record ScanReport(
    string Target,
    DateTimeOffset ScannedAt,
    int Score,
    Severity Risk,
    IReadOnlyList<Finding> Findings)
{
    public bool HasAtLeast(Severity threshold) => Findings.Any(f => f.Severity >= threshold);
}
