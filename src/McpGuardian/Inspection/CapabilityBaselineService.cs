using System.Security.Cryptography;
using System.Text.Json;

namespace McpGuardian.Inspection;

public sealed class CapabilityBaselineService
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public CapabilityBaseline Create(InspectionReport report) => new(
        1, report.Server, DateTimeOffset.UtcNow,
        report.Tools.ToDictionary(tool => tool.Name, tool => tool.Fingerprint, StringComparer.Ordinal));

    public void Save(CapabilityBaseline baseline, string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        File.WriteAllText(path, JsonSerializer.Serialize(baseline, Options) + Environment.NewLine);
    }

    public CapabilityVerification Verify(InspectionReport report, string baselinePath)
    {
        var baseline = JsonSerializer.Deserialize<CapabilityBaseline>(File.ReadAllText(baselinePath))
            ?? throw new InvalidDataException("Capability baseline is empty.");
        if (baseline.Version != 1) throw new InvalidDataException($"Unsupported capability baseline version: {baseline.Version}.");
        if (!string.Equals(baseline.Server, report.Server, StringComparison.Ordinal))
            throw new InvalidDataException($"Capability baseline belongs to server '{baseline.Server}', not '{report.Server}'.");

        var current = report.Tools.ToDictionary(tool => tool.Name, tool => tool.Fingerprint, StringComparer.Ordinal);
        var changes = new List<CapabilityChange>();
        changes.AddRange(current.Keys.Except(baseline.Tools.Keys, StringComparer.Ordinal)
            .Select(tool => new CapabilityChange(tool, CapabilityChangeKind.Added)));
        changes.AddRange(baseline.Tools.Keys.Except(current.Keys, StringComparer.Ordinal)
            .Select(tool => new CapabilityChange(tool, CapabilityChangeKind.Removed)));
        foreach (var tool in current.Keys.Intersect(baseline.Tools.Keys, StringComparer.Ordinal))
        {
            if (!SafeEquals(current[tool], baseline.Tools[tool])) changes.Add(new CapabilityChange(tool, CapabilityChangeKind.Modified));
        }
        return new CapabilityVerification(changes.OrderBy(change => change.Tool, StringComparer.Ordinal).ToArray());
    }

    private static bool SafeEquals(string left, string right)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
        }
        catch (FormatException)
        {
            throw new InvalidDataException("Capability baseline contains an invalid fingerprint.");
        }
    }
}
