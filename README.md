# MCP Guardian

Security scanner and policy gateway for the Model Context Protocol.

MCP Guardian audits MCP client configuration before a server is trusted. It finds risky package resolution, embedded credentials, overly broad filesystem access, shell-based launchers, dangerous flags, and unencrypted remote transports. The CLI produces human-readable or JSON reports and can block CI when findings cross a chosen severity.

> [!IMPORTANT]
> This project is an early security tool. A clean scan is not proof that an MCP server is safe; review server code, provenance, requested capabilities, and runtime behavior.

## Quick start

Requires the .NET 7 SDK or newer.

```bash
dotnet run --project src/McpGuardian -- scan examples/vulnerable/mcp.json
```

JSON output and CI failure threshold:

```bash
dotnet run --project src/McpGuardian -- \
  scan .mcp.json --format json --fail-on high
```

Example output:

```text
MCP Guardian — /path/to/mcp.json
Risk: CRITICAL | Score: 84/100 | Findings: 4

[CRITICAL] MCG105 Hard-coded credential (filesystem)
  Environment variable 'API_TOKEN' appears to contain a literal credential.
```

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `MCG001` | High | Invalid or missing `mcpServers` configuration |
| `MCG101` | Critical | MCP servers launched through a command shell |
| `MCG102` | High | npm packages without an exact version |
| `MCG103` | High | Filesystem root or home-directory access |
| `MCG104` | High | Non-local remote MCP endpoints using HTTP |
| `MCG105` | Critical | Credentials embedded directly in configuration |
| `MCG106` | Critical | Explicit broad-permission or dangerous flags |

## Security model

MCP servers are software installed into an agent's trust boundary. Local stdio servers inherit the permissions of the client that starts them, while remote servers introduce identity, transport, authorization, and token-handling risks.

MCP Guardian follows these principles:

- Treat tool definitions and configuration as untrusted input.
- Prefer exact, reviewed dependencies and narrow capabilities.
- Keep credentials out of configuration and logs.
- Require TLS for remote transports.
- Make security decisions deterministic and enforce them outside the model.

See the [official MCP security considerations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx) and the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## Roadmap

- Tool-schema fingerprinting and change detection
- Runtime allow/deny policy gateway
- OAuth audience, resource indicator, and token-passthrough checks
- SARIF and GitHub Code Scanning integration
- Adversarial MCP test lab for tool poisoning, injection, SSRF, and confused-deputy attacks
- Signed release binaries for Linux, macOS, and Windows

## Development

The test runner intentionally has no third-party dependencies.

```bash
dotnet build src/McpGuardian/McpGuardian.csproj
dotnet run --project tests/McpGuardian.Tests/McpGuardian.Tests.csproj
```

## Responsible disclosure

Do not open public issues for suspected vulnerabilities. Follow [SECURITY.md](SECURITY.md) to report them privately.

## License

MIT
