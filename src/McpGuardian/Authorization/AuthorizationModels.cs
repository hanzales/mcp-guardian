using System.Text.Json;
using McpGuardian.Models;

namespace McpGuardian.Authorization;

public sealed record AuthorizationAuditInput(
    Uri ResourceUrl,
    JsonElement ProtectedResourceMetadata,
    JsonElement AuthorizationServerMetadata,
    IReadOnlyList<Uri>? RedirectUris,
    bool? SendsResourceParameter,
    bool? ValidatesTokenAudience,
    bool? AcceptsUpstreamTokens,
    bool? ForwardsBearerTokens,
    bool? ValidatesAuthorizationResponseIssuer,
    bool? RateLimitingEnabled,
    bool? SecurityLoggingEnabled,
    IReadOnlyList<string>? CorsAllowedOrigins,
    IReadOnlyList<string>? AllowedHosts);

public sealed record AuthorizationAuditReport(
    int Version,
    string Source,
    DateTimeOffset AuditedAt,
    IReadOnlyList<Finding> Findings)
{
    public bool HasAtLeast(Severity threshold) => Findings.Any(finding => finding.Severity >= threshold);
}
