using System.Text.Json;
using McpGuardian.Models;

namespace McpGuardian.Authorization;

public sealed class AuthorizationAuditor
{
    public AuthorizationAuditReport Audit(AuthorizationAuditInput input, string source)
    {
        var findings = new List<Finding>();
        var resource = String(input.ProtectedResourceMetadata, "resource");
        if (resource is null || !Uri.TryCreate(resource, UriKind.Absolute, out var resourceUri) || !SameCanonicalResource(resourceUri, input.ResourceUrl))
            Add(findings, "MCG301", Severity.High, "Protected Resource Metadata mismatch", "The resource identifier is missing, invalid, or does not match the canonical MCP server URI.", "Publish RFC 9728 metadata with the canonical MCP resource URI.");

        var authorizationServers = Strings(input.ProtectedResourceMetadata, "authorization_servers");
        if (authorizationServers.Count == 0)
            Add(findings, "MCG302", Severity.Critical, "Missing authorization server", "Protected Resource Metadata does not advertise an authorization server.", "Add at least one authorization_servers entry as required by MCP authorization discovery.");
        foreach (var server in authorizationServers)
            if (!SecureUri(server)) Add(findings, "MCG302", Severity.High, "Insecure authorization server URI", "An authorization server URI is not HTTPS or loopback.", "Serve authorization metadata and endpoints over HTTPS.");

        var issuer = String(input.AuthorizationServerMetadata, "issuer");
        if (issuer is null || !authorizationServers.Contains(issuer, StringComparer.Ordinal))
            Add(findings, "MCG303", Severity.Critical, "Authorization issuer mismatch", "Authorization Server Metadata issuer does not exactly match an advertised issuer.", "Reject mismatched metadata and publish the exact discovery issuer value.");

        foreach (var endpointName in new[] { "authorization_endpoint", "token_endpoint" })
        {
            var endpoint = String(input.AuthorizationServerMetadata, endpointName);
            if (endpoint is null || !SecureUri(endpoint)) Add(findings, "MCG304", Severity.High, "Missing or insecure OAuth endpoint", $"{endpointName} is missing or is not HTTPS/loopback.", "Publish secure OAuth authorization and token endpoints.");
        }

        if (!Strings(input.AuthorizationServerMetadata, "code_challenge_methods_supported").Contains("S256", StringComparer.Ordinal))
            Add(findings, "MCG305", Severity.Critical, "PKCE S256 unavailable", "Authorization Server Metadata does not advertise PKCE S256.", "Advertise and enforce code_challenge_method=S256; MCP clients must refuse flows without it.");
        if (input.SendsResourceParameter != true)
            Add(findings, "MCG306", Severity.High, "Resource indicator not verified", "Evidence does not confirm the canonical resource parameter in authorization and token requests.", "Include the canonical MCP resource URI in both requests per RFC 8707.");
        if (input.ValidatesTokenAudience != true)
            Add(findings, "MCG307", Severity.Critical, "Token audience validation not verified", "Evidence does not confirm that tokens are restricted to this MCP resource.", "Validate issuer and audience and reject tokens not issued specifically for this MCP server.");

        foreach (var redirect in input.RedirectUris ?? [])
            if (!SecureRedirect(redirect)) Add(findings, "MCG308", Severity.High, "Unsafe redirect URI", "A redirect URI is neither HTTPS nor loopback HTTP.", "Register exact HTTPS redirect URIs or loopback redirects for native clients.");
        if (input.RedirectUris is null or { Count: 0 })
            Add(findings, "MCG308", Severity.Medium, "Redirect URI evidence missing", "No registered redirect URI evidence was provided.", "Document and validate exact pre-registered redirect URIs.");

        if (input.AcceptsUpstreamTokens == true || input.ForwardsBearerTokens == true)
            Add(findings, "MCG309", Severity.Critical, "Token passthrough risk", "Evidence indicates that third-party or inbound bearer tokens may be accepted or forwarded.", "Never transit tokens; exchange for audience-bound tokens and accept only tokens issued for this resource.");
        if (input.ValidatesAuthorizationResponseIssuer != true)
            Add(findings, "MCG310", Severity.High, "Mix-up protection not verified", "Authorization response issuer validation is not confirmed.", "Record the discovered issuer and validate the RFC 9207 iss response value before token exchange.");

        if (input.CorsAllowedOrigins?.Any(origin => origin == "*" || origin.Equals("null", StringComparison.OrdinalIgnoreCase)) == true)
            Add(findings, "MCG311", Severity.High, "Broad CORS policy", "CORS allows a wildcard or null origin.", "Allowlist exact trusted origins and avoid credentialed wildcard access.");
        if (input.AllowedHosts is null or { Count: 0 }) Add(findings, "MCG312", Severity.Medium, "Host allowlist missing", "No allowed-host policy evidence was provided.", "Validate Host headers against an explicit allowlist.");
        if (input.RateLimitingEnabled != true) Add(findings, "MCG313", Severity.Medium, "Rate limiting not verified", "Authorization endpoint rate limiting is not confirmed.", "Apply rate limits to discovery, authorization, token, and MCP endpoints.");
        if (input.SecurityLoggingEnabled != true) Add(findings, "MCG314", Severity.Low, "Security logging not verified", "Security-relevant authorization logging is not confirmed.", "Log failures and policy decisions without recording tokens, codes, or secrets.");

        var registration = String(input.AuthorizationServerMetadata, "registration_endpoint");
        var clientMetadataSupported = input.AuthorizationServerMetadata.TryGetProperty("client_id_metadata_document_supported", out var clientMetadata) && clientMetadata.ValueKind == JsonValueKind.True;
        if (!clientMetadataSupported && (registration is null || !SecureUri(registration)))
            Add(findings, "MCG315", Severity.Medium, "Client registration mechanism unclear", "Metadata advertises neither Client ID Metadata Documents nor Dynamic Client Registration.", "Prefer Client ID Metadata Documents, pre-registration, or retain DCR only for compatibility.");

        return new AuthorizationAuditReport(1, Path.GetFullPath(source), DateTimeOffset.UtcNow, findings);
    }

    private static void Add(ICollection<Finding> findings, string id, Severity severity, string title, string message, string fix) =>
        findings.Add(new Finding(id, severity, "authorization", title, message, fix));
    private static string? String(JsonElement value, string name) => value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
    private static IReadOnlyList<string> Strings(JsonElement value, string name) => value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.Array ? item.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToArray() : [];
    private static bool SecureUri(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) && string.IsNullOrEmpty(uri.Fragment) && (uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback));
    private static bool SecureRedirect(Uri uri) => uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback);
    private static bool SameCanonicalResource(Uri left, Uri right) =>
        left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        left.Host.Equals(right.Host, StringComparison.OrdinalIgnoreCase) && left.Port == right.Port &&
        left.AbsolutePath.TrimEnd('/').Equals(right.AbsolutePath.TrimEnd('/'), StringComparison.Ordinal) &&
        left.Query.Equals(right.Query, StringComparison.Ordinal) && string.IsNullOrEmpty(left.Fragment);
}
