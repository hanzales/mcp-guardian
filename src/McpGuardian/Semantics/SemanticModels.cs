using McpGuardian.Models;

namespace McpGuardian.Semantics;

public sealed record SemanticReport(
    int Version,
    DateTimeOffset AnalyzedAt,
    IReadOnlyList<string> Sources,
    IReadOnlyList<Finding> Findings)
{
    public bool HasAtLeast(Severity threshold) => Findings.Any(finding => finding.Severity >= threshold);
}
