namespace McpGuardian.Baselines;

public sealed record BaselineDocument(
    int Version,
    string Source,
    DateTimeOffset CreatedAt,
    IReadOnlyDictionary<string, string> Servers);

public enum BaselineChangeKind
{
    Added,
    Removed,
    Modified
}

public sealed record BaselineChange(string Server, BaselineChangeKind Kind);

public sealed record BaselineVerification(
    string ConfigPath,
    string BaselinePath,
    IReadOnlyList<BaselineChange> Changes)
{
    public bool IsMatch => Changes.Count == 0;
}
