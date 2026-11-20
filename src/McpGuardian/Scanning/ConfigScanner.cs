using System.Text.Json;
using System.Text.RegularExpressions;
using McpGuardian.Models;

namespace McpGuardian.Scanning;

public sealed partial class ConfigScanner
{
    private static readonly HashSet<string> Shells = new(StringComparer.OrdinalIgnoreCase)
    {
        "sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"
    };

    private static readonly string[] SensitiveNameFragments =
    {
        "TOKEN", "SECRET", "PASSWORD", "API_KEY", "PRIVATE_KEY", "CREDENTIAL"
    };

    public ScanReport Scan(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        });

        var findings = new List<Finding>();
        if (!TryGetServers(document.RootElement, out var servers))
        {
            findings.Add(new Finding(
                "MCG001", Severity.High, "configuration", "Missing MCP servers object",
                "The file does not contain a valid top-level mcpServers or servers object.",
                "Use the configuration shape documented by the target MCP client."));
            return BuildReport(path, findings);
        }

        foreach (var serverProperty in servers.EnumerateObject())
        {
            ScanServer(serverProperty.Name, serverProperty.Value, findings);
        }

        return BuildReport(path, findings);
    }

    private static void ScanServer(string name, JsonElement server, ICollection<Finding> findings)
    {
        var command = GetString(server, "command");
        var args = GetStrings(server, "args");
        var url = GetString(server, "url");

        if (!string.IsNullOrWhiteSpace(command) && Shells.Contains(Path.GetFileName(command)))
        {
            findings.Add(new Finding(
                "MCG101", Severity.Critical, name, "Shell-based server launch",
                $"The server is launched through '{command}', which expands the command-injection surface.",
                "Execute a fixed binary directly and pass arguments as an array."));
        }

        if (string.Equals(Path.GetFileName(command), "npx", StringComparison.OrdinalIgnoreCase))
        {
            var package = args.FirstOrDefault(a => !a.StartsWith('-'));
            if (package is not null && !IsPinnedNpmPackage(package))
            {
                findings.Add(new Finding(
                    "MCG102", Severity.High, name, "Unpinned npm package",
                    $"Package '{package}' is resolved without an exact version and may change between launches.",
                    "Pin the package to an exact reviewed version, for example package@1.2.3."));
            }
        }

        foreach (var arg in args)
        {
            if (IsBroadPath(arg))
            {
                findings.Add(new Finding(
                    "MCG103", Severity.High, name, "Broad filesystem scope",
                    $"Argument '{arg}' may expose a home directory or filesystem root.",
                    "Allowlist the smallest directory the server needs."));
            }
        }

        if (Uri.TryCreate(url, UriKind.Absolute, out var endpoint) && endpoint.Scheme == Uri.UriSchemeHttp &&
            !endpoint.IsLoopback)
        {
            findings.Add(new Finding(
                "MCG104", Severity.High, name, "Unencrypted remote transport",
                $"Remote MCP endpoint '{url}' uses HTTP.",
                "Use HTTPS and validate the remote server identity."));
        }

        if (server.TryGetProperty("env", out var env) && env.ValueKind == JsonValueKind.Object)
        {
            foreach (var variable in env.EnumerateObject())
            {
                var value = variable.Value.ValueKind == JsonValueKind.String ? variable.Value.GetString() : null;
                if (IsSensitiveName(variable.Name) && IsLiteralSecret(value))
                {
                    findings.Add(new Finding(
                        "MCG105", Severity.Critical, name, "Hard-coded credential",
                        $"Environment variable '{variable.Name}' appears to contain a literal credential.",
                        "Reference a secret manager or an inherited environment variable instead."));
                }
            }
        }

        if (args.Any(a => a.Contains("--dangerously", StringComparison.OrdinalIgnoreCase) ||
                          a.Contains("--allow-all", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding(
                "MCG106", Severity.Critical, name, "Dangerous permission override",
                "The command enables a broad or explicitly dangerous permission flag.",
                "Remove the override and grant only the required capabilities."));
        }
    }

    private static ScanReport BuildReport(string path, IReadOnlyList<Finding> findings)
    {
        var score = Math.Min(100, findings.Sum(f => f.Severity switch
        {
            Severity.Critical => 30,
            Severity.High => 18,
            Severity.Medium => 8,
            Severity.Low => 3,
            _ => 0
        }));

        var risk = score switch
        {
            >= 70 => Severity.Critical,
            >= 40 => Severity.High,
            >= 15 => Severity.Medium,
            > 0 => Severity.Low,
            _ => Severity.Info
        };

        return new ScanReport(Path.GetFullPath(path), DateTimeOffset.UtcNow, score, risk, findings);
    }

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool TryGetServers(JsonElement root, out JsonElement servers)
    {
        if (root.TryGetProperty("mcpServers", out servers) && servers.ValueKind == JsonValueKind.Object)
        {
            return true;
        }

        return root.TryGetProperty("servers", out servers) && servers.ValueKind == JsonValueKind.Object;
    }

    private static IReadOnlyList<string> GetStrings(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String)
                .Select(v => v.GetString()!).ToArray()
            : Array.Empty<string>();

    private static bool IsPinnedNpmPackage(string package)
    {
        var separator = package.LastIndexOf('@');
        if (separator <= 0 || separator == package.Length - 1)
        {
            return false;
        }

        return ExactVersionRegex().IsMatch(package[(separator + 1)..]);
    }

    private static bool IsBroadPath(string value) => value is "/" or "~" or "$HOME" or "${HOME}" ||
                                                       value.Equals(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.Ordinal);

    private static bool IsSensitiveName(string name) =>
        SensitiveNameFragments.Any(fragment => name.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    private static bool IsLiteralSecret(string? value) => !string.IsNullOrWhiteSpace(value) &&
                                                          !value.StartsWith("${", StringComparison.Ordinal) &&
                                                          !value.StartsWith("$", StringComparison.Ordinal) &&
                                                          !value.StartsWith("secret://", StringComparison.OrdinalIgnoreCase) &&
                                                          value.Length >= 8;

    [GeneratedRegex(@"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")]
    private static partial Regex ExactVersionRegex();
}
