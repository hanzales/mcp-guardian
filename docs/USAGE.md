# Usage guide

This guide describes practical MCP Guardian workflows. Commands assume the tool is installed globally; replace `mcp-guardian` with `dotnet run --project src/McpGuardian --` when running from source.

## Review an MCP configuration before enabling it

1. Obtain the configuration from a trusted source.
2. Inspect package names, versions, commands, arguments, URLs, environment variables, and filesystem paths manually.
3. Run Guardian:

   ```bash
   mcp-guardian scan proposed-mcp.json --fail-on high
   ```

4. Resolve findings or document accepted risk.
5. Move the reviewed configuration into the client-specific location.
6. Create a trusted baseline:

   ```bash
   mcp-guardian baseline create .mcp.json
   ```

A clean scan is not approval by itself. Guardian cannot prove that a referenced package or remote server behaves as declared.

## Audit the current workstation

```bash
mcp-guardian discover
mcp-guardian scan --all
mcp-guardian scan --all --fail-on high
```

The discovery command only reports paths; it does not modify client settings or start MCP servers.

## Produce machine-readable reports

```bash
mcp-guardian scan .mcp.json --format json --output artifacts/mcp-guardian.json
mcp-guardian scan .mcp.json --format sarif --output artifacts/mcp-guardian.sarif
```

Reports never include detected secret values. Finding messages identify the environment variable name, server name, rule, severity, and remediation.

## Use a baseline in pull requests

```bash
mcp-guardian baseline create .mcp.json
git add .mcp-guardian.baseline.json
git commit -m "security: trust reviewed MCP configuration"
mcp-guardian baseline verify .mcp.json
```

When drift is intentional, review the complete configuration change and regenerate the baseline in the same pull request. Never update a baseline merely to silence CI.

## Inspect a live MCP server

Always run the static scanner and review its findings before live inspection:

```bash
mcp-guardian scan .mcp.json --fail-on high
```

Streamable HTTP inspection connects to the configured `url`. Stdio inspection starts the configured command and therefore requires explicit process consent:

```bash
mcp-guardian inspect .mcp.json --server remote --format json
mcp-guardian inspect .mcp.json --server local --allow-process
```

Guardian initializes the MCP session, records the negotiated protocol version and server identity, sends `notifications/initialized`, and exports advertised tools, resources, and prompts. It follows list cursors but stops after 100 pages. It does not invoke tools, read resources, or render prompts.

Create a trusted capability baseline after reviewing the complete export, then verify it later or in CI:

```bash
mcp-guardian inspect .mcp.json --server local --allow-process \
  --format json --output artifacts/local-capabilities.json \
  --save-baseline security/local-tools.json

mcp-guardian inspect .mcp.json --server local --allow-process \
  --baseline security/local-tools.json
```

Exit code `1` means a tool was added, removed, or modified. Capability baselines contain only tool names and SHA-256 fingerprints; inspection reports intentionally contain the server-provided schemas and descriptions.

Bound resource use when inspecting an unfamiliar server:

```bash
mcp-guardian inspect .mcp.json --server remote \
  --timeout 5 --max-response-bytes 262144
```

Timeouts and response limits apply to each exchange. HTTP redirects are rejected, stdio stderr is drained without retention, and child processes are terminated when inspection succeeds or fails. Run untrusted servers in an OS-level sandbox or disposable environment; Guardian does not provide process isolation.

## Analyze semantic attack surfaces

The `analyze` command consumes JSON reports produced by `inspect`. It is offline and does not reconnect to MCP servers:

```bash
mcp-guardian analyze artifacts/server-a.json
mcp-guardian analyze artifacts/server-a.json artifacts/server-b.json --fail-on high
mcp-guardian analyze artifacts/*.json --format json --output artifacts/semantic-report.json
```

Supplying multiple reports enables tool-name shadowing and cross-server data-flow checks. Findings describe the indicator without reproducing untrusted instructions. Treat them as review signals: descriptions and annotations are untrusted metadata, and a clean report cannot prove that implementation behavior is safe.

The repository includes regression fixtures:

```bash
mcp-guardian analyze examples/security-lab/safe-inspection.json --fail-on low
mcp-guardian analyze \
  examples/security-lab/poisoned-inspection.json \
  examples/security-lab/shadow-inspection.json \
  --fail-on high
```

The safe fixture exits `0`; the vulnerable pair exits `1`. AI-assisted explanations are not enabled in v0.4, so analysis requires no API, account, network connection, or model trust.

## Audit MCP authorization evidence

Copy the secure authorization-lab fixture and replace its example values with reviewed metadata and implementation evidence:

```bash
cp examples/authorization-lab/secure.json authorization-evidence.json
mcp-guardian audit-auth authorization-evidence.json --fail-on high
```

The `protectedResourceMetadata` and `authorizationServerMetadata` objects should be exact documents obtained through the MCP discovery flow. The remaining fields record implementation evidence for behavior that static metadata cannot prove, including audience validation, resource parameters, token forwarding, issuer validation, rate limiting, CORS, host validation, and secret-safe logging.

This command is passive and offline. It never performs OAuth registration, redirects a browser, exchanges a code, submits a token, or treats self-attested evidence as runtime proof. Keep tokens, authorization codes, client secrets, and user data out of the evidence file.

## Protect a stdio server with the runtime gateway

```bash
mcp-guardian gateway .mcp.json --server filesystem \
  --policy examples/gateway/policy.json --allow-process \
  --audit .mcp-guardian-audit.jsonl
```

Configure the MCP client to launch this gateway command instead of launching the underlying server directly. The gateway communicates over stdin/stdout, starts the configured command without a shell, and keeps diagnostics and audit data off the protocol stream.

Policy actions are `allow`, `deny`, and `approval`. In v0.6, `approval` is fail-closed and returns an approval-required JSON-RPC error; it cannot yet resume a call. Paths must remain under an allowlisted root and URL arguments must target an allowlisted host. Audit records store only argument hashes and chained event hashes, not raw arguments.

## Severity policies

```bash
# Block only critical findings
mcp-guardian scan .mcp.json --fail-on critical

# Block high and critical findings
mcp-guardian scan .mcp.json --fail-on high

# Strict policy: block every current rule
mcp-guardian scan .mcp.json --fail-on low
```

## Troubleshooting

### `Missing MCP servers object`

Guardian currently expects the common JSON shape:

```json
{
  "mcpServers": {
    "example": {
      "command": "example-server",
      "args": []
    }
  }
}
```

VS Code's equivalent top-level `servers` object is also supported. Some clients wrap MCP configuration in another object or store it in TOML. Those formats require a future adapter.

### No configurations discovered

Pass the file explicitly:

```bash
mcp-guardian scan /path/to/client-config.json
```

Then open an issue with the client name and documented configuration location if it should be supported.

### A package is reported as unpinned

Use an exact semantic version:

```json
"args": ["@vendor/server@1.2.3"]
```

Tags such as `latest`, version ranges, Git branches, and missing versions are intentionally not considered pinned.

### Baseline drift occurs after formatting

Whitespace and JSON object property order are canonicalized. Array order remains significant because it can change command behavior. If formatting alone causes drift, report it as a bug with a minimal redacted example.
