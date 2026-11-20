# MCP Guardian

[![CI](https://github.com/hanzales/mcp-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/hanzales/mcp-guardian/actions/workflows/ci.yml)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security scanner and policy foundation for the Model Context Protocol.

MCP Guardian audits MCP client configuration before a server is trusted. It detects risky package resolution, embedded credentials, overly broad filesystem access, shell-based launchers, dangerous flags, and unencrypted remote transports. Reports can be emitted as text, JSON, or SARIF and enforced in CI.

Version `0.3` adds explicit live capability inspection over stdio and Streamable HTTP, paginated capability export, canonical tool fingerprints, and tool-schema drift detection.

> [!IMPORTANT]
> MCP Guardian reduces known configuration risks; it does not prove that an MCP server is safe. Review server provenance, source code, requested capabilities, authorization behavior, and runtime activity.

## Features

- Deterministic scanning with clear remediation guidance
- Automatic discovery for supported Claude, Cursor, VS Code, and project configurations
- Text, JSON, and SARIF 2.1.0 reports
- CI policy gates through severity-based exit codes
- Canonical SHA-256 fingerprints for trusted MCP server definitions
- Detection of added, removed, and modified server configurations
- Opt-in live MCP inspection over stdio and Streamable HTTP
- Protocol, server, and capability inventory with tools, resources, and prompts export
- Canonical tool fingerprints with added, removed, and modified tool detection
- Bounded inspection time, response sizes, pagination, redirects, and child-process lifetime
- Dependency-free runtime and test runner
- Packaged as a .NET global tool

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

The repository pins SDK `10.0.404` through [`global.json`](global.json). A newer compatible .NET 10 feature band can be used through `rollForward`.

## Quick start

```bash
git clone https://github.com/hanzales/mcp-guardian.git
cd mcp-guardian
dotnet run --project src/McpGuardian -- scan examples/vulnerable/mcp.json
```

Expected summary:

```text
Risk: CRITICAL | Score: 84/100 | Findings: 4
```

Scan a real configuration and fail when a high or critical finding is detected:

```bash
dotnet run --project src/McpGuardian -- \
  scan .mcp.json --fail-on high
```

## Install as a local .NET tool

Until packages are published to NuGet, build and install directly from the repository:

```bash
dotnet pack src/McpGuardian/McpGuardian.csproj \
  --configuration Release \
  --output ./artifacts

dotnet tool install --global \
  --add-source ./artifacts \
  McpGuardian.Tool
```

Then use it from any directory:

```bash
mcp-guardian version
mcp-guardian discover
mcp-guardian scan .mcp.json
```

## Commands

### Discover configurations

```bash
mcp-guardian discover
mcp-guardian discover --json
```

Discovery checks project-local and user-level locations used by Claude Desktop, Claude Code JSON configurations, Cursor, VS Code, and project-level `.mcp.json` files. Only files that exist are returned. TOML and proprietary databases are not parsed in this release.

### Scan

```bash
mcp-guardian scan <config>
mcp-guardian scan <config> --format json
mcp-guardian scan <config> --format sarif --output guardian.sarif
mcp-guardian scan <config> --fail-on high
mcp-guardian scan --all --fail-on critical
```

`--all` scans every supported configuration found by `discover`.

### Create and verify a trusted baseline

Create a baseline after manually reviewing a configuration:

```bash
mcp-guardian baseline create .mcp.json
```

This writes `.mcp-guardian.baseline.json` beside the configuration. Each server definition is canonicalized and hashed with SHA-256; secrets and raw configuration values are not copied into the baseline.

Verify it later:

```bash
mcp-guardian baseline verify .mcp.json
```

Guardian returns exit code `1` if a server was added, removed, or modified. Property reordering and whitespace changes do not create false drift.

Custom baseline location:

```bash
mcp-guardian baseline create .mcp.json --output security/mcp-baseline.json
mcp-guardian baseline verify .mcp.json --baseline security/mcp-baseline.json
```

### Inspect live capabilities

Live inspection performs an MCP handshake and requests the capabilities advertised by one configured server. It is separate from the side-effect-free `scan` command.

```bash
# Remote Streamable HTTP server
mcp-guardian inspect .mcp.json --server remote --format json

# Local stdio server; the extra flag explicitly permits process execution
mcp-guardian inspect .mcp.json --server filesystem --allow-process
```

Export a report and create a reviewed tool-schema baseline:

```bash
mcp-guardian inspect .mcp.json --server filesystem --allow-process \
  --format json --output artifacts/filesystem-capabilities.json \
  --save-baseline security/filesystem-capabilities.baseline.json
```

Detect tools that were added, removed, or modified:

```bash
mcp-guardian inspect .mcp.json --server filesystem --allow-process \
  --baseline security/filesystem-capabilities.baseline.json
```

Inspection defaults to a 10-second timeout and a 1 MiB limit per response. Override them with `--timeout <seconds>` and `--max-response-bytes <bytes>`. Pagination is capped at 100 pages. HTTP redirects are disabled, stderr is drained without retention, and a launched stdio process is terminated after inspection.

> [!WARNING]
> Live inspection communicates with untrusted software. Review the static `scan` result first, use an isolated environment, and do not inspect a server with credentials or privileges it does not need. Guardian inventories metadata; it never calls an advertised tool.

## Output formats

| Format | Intended use |
| --- | --- |
| `text` | Local terminal and human review |
| `json` | Automation and custom integrations |
| `sarif` | GitHub Code Scanning and SARIF-compatible platforms |

Write any format to a file with `--output`:

```bash
mcp-guardian scan .mcp.json --format json --output reports/guardian.json
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Command completed and the selected policy passed |
| `1` | A finding reached `--fail-on`, or configuration/capability drift was detected |
| `2` | Invalid arguments, unreadable input, or malformed configuration |

## Detection rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `MCG001` | High | Invalid or missing `mcpServers` / `servers` configuration |
| `MCG101` | Critical | MCP servers launched through a command shell |
| `MCG102` | High | npm packages without an exact version |
| `MCG103` | High | Filesystem root or home-directory access |
| `MCG104` | High | Non-local remote MCP endpoints using HTTP |
| `MCG105` | Critical | Credentials embedded directly in configuration |
| `MCG106` | Critical | Explicit broad-permission or dangerous flags |

See [docs/USAGE.md](docs/USAGE.md) for detailed workflows and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and trust boundaries.

## GitHub Actions

The repository CI builds and tests the tool, verifies the secure fixture, produces SARIF, uploads findings to GitHub Code Scanning, and packages the .NET tool.

For another repository, build Guardian and run:

```yaml
- name: Scan MCP configuration
  run: >-
    dotnet run --project tools/mcp-guardian/src/McpGuardian --
    scan .mcp.json
    --format sarif
    --output artifacts/mcp-guardian.sarif
    --fail-on high
```

A reusable standalone GitHub Action is planned for a later release.

## Security model

Local stdio MCP servers run with the privileges of the client that starts them. Remote servers add transport, identity, authorization, token, and data-exfiltration risks. Guardian therefore follows these principles:

- Treat configuration and tool metadata as untrusted input.
- Prefer exact, reviewed dependencies and narrow capabilities.
- Keep credentials out of configuration, reports, and logs.
- Require encrypted transport for non-local endpoints.
- Keep enforcement deterministic and outside the language model.
- Detect trust changes instead of assuming a previously reviewed server is unchanged.

See the [official MCP security considerations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx) and the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## Project structure

```text
src/McpGuardian/
├── Baselines/    Canonical fingerprints and drift detection
├── Cli/          Commands and report writers
├── Discovery/    Client configuration discovery
├── Models/       Shared report contracts
└── Scanning/     Deterministic detection rules

tests/McpGuardian.Tests/  Dependency-free executable test suite
examples/                 Secure and vulnerable configurations
docs/                     Usage and architecture documentation
```

## Development

```bash
dotnet restore mcp-guardian.slnx
dotnet build mcp-guardian.slnx --configuration Release --no-restore
dotnet run --project tests/McpGuardian.Tests/McpGuardian.Tests.csproj \
  --configuration Release --no-build
```

The test project intentionally uses no third-party test framework, keeping restore and supply-chain exposure minimal.

## Roadmap

The next milestones include live MCP capability inspection, tool-schema fingerprinting, tool-poisoning checks, OAuth compliance auditing, and a runtime policy gateway. See [ROADMAP.md](ROADMAP.md).

## Responsible disclosure

Do not open public issues for suspected vulnerabilities. Follow [SECURITY.md](SECURITY.md) to report them privately.

## License

[MIT](LICENSE)
