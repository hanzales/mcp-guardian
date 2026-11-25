# MCP Guardian

[![CI](https://github.com/hanzales/mcp-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/hanzales/mcp-guardian/actions/workflows/ci.yml)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Security scanner and policy foundation for the Model Context Protocol.

MCP Guardian audits MCP client configuration before a server is trusted. It detects risky package resolution, embedded credentials, overly broad filesystem access, shell-based launchers, dangerous flags, and unencrypted remote transports. Reports can be emitted as text, JSON, or SARIF and enforced in CI.

Version `0.6` begins the runtime policy gateway: a bounded stdio proxy with per-server/tool policy, path and network constraints, approval-required blocking, and secret-safe hash-chain audit events.

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
- Offline semantic analysis of one or more inspection reports
- MCP Security Lab fixtures for safe, poisoned, and cross-server attack surfaces
- Authorization evidence auditing with 15 stable OAuth/MCP security rules
- Runtime stdio policy gateway with default-deny policy and resource limits
- Dependency-free runtime and test runner
- Packaged as a .NET global tool

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

The repository pins SDK `10.0.404` through [`global.json`](global.json). A newer compatible .NET 10 feature band can be used through `rollForward`.

Confirm that the active SDK is .NET 10 before installing the tool:

```bash
dotnet --version
dotnet --list-sdks
```

MCP Guardian is a .NET tool, not a project library. Do not install it through
Rider's NuGet Packages window or add it as a `<PackageReference>`.

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

## Install

Install the preview from NuGet.org as a global tool:

```bash
dotnet tool install --global McpGuardian.Tool \
  --version 0.6.0-preview.2 \
  --add-source https://api.nuget.org/v3/index.json \
  --ignore-failed-sources
```

The explicit source and `--ignore-failed-sources` prevent an unavailable private
feed from blocking installation. Then use Guardian from any directory:

```bash
mcp-guardian version
mcp-guardian discover
mcp-guardian scan .mcp.json
```

To pin Guardian per repository instead, run these commands at the repository root:

```bash
dotnet new tool-manifest
dotnet tool install McpGuardian.Tool \
  --version 0.6.0-preview.2 \
  --add-source https://api.nuget.org/v3/index.json \
  --ignore-failed-sources

dotnet tool run mcp-guardian version
```

### Standalone downloads

[GitHub Releases](https://github.com/hanzales/mcp-guardian/releases) also provides
self-contained executables that do not require a separate .NET installation:

- `mcp-guardian-osx-arm64` for Apple Silicon Macs
- `mcp-guardian-osx-x64` for Intel Macs
- `mcp-guardian-linux-x64` for 64-bit Linux
- `mcp-guardian-win-x64.exe` for 64-bit Windows

On macOS or Linux, make the downloaded file executable before running it:

```bash
chmod +x mcp-guardian-osx-arm64
./mcp-guardian-osx-arm64 version
```

### Installation troubleshooting

If installation reports that the package supports `net10.0` but the current
framework is older, the wrong SDK is active. Check every installed SDK and host:

```bash
which -a dotnet        # macOS/Linux
dotnet --version
dotnet --list-sdks
```

Install the .NET 10 SDK or place its directory before older installations in
`PATH`, then open a new terminal. A successful global installation appears in:

```bash
dotnet tool list --global
```

If the tool is listed but the `mcp-guardian` command is not found, add the global
tool directory to `PATH`:

```bash
export PATH="$HOME/.dotnet/tools:$PATH"
```

See Microsoft's [.NET tool troubleshooting guide](https://learn.microsoft.com/dotnet/core/tools/troubleshoot-usage-issues) for platform-specific host and PATH diagnostics.

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

### Analyze the semantic attack surface

Run semantic analysis against one inspection report or compare multiple servers:

```bash
mcp-guardian analyze artifacts/filesystem-capabilities.json

mcp-guardian analyze \
  artifacts/filesystem-capabilities.json \
  artifacts/network-capabilities.json \
  --format json \
  --fail-on high
```

The analyzer detects instruction-like tool poisoning, invisible Unicode controls, encoded instructions, schema/annotation contradictions, duplicate tool names across servers, explicit cross-server invocation instructions, and risky data-source-to-network-sink combinations. It never executes server-provided text or copies matched instructions into findings.

Try the intentionally vulnerable security lab:

```bash
mcp-guardian analyze \
  examples/security-lab/poisoned-inspection.json \
  examples/security-lab/shadow-inspection.json \
  --fail-on high
```

Semantic checks are deterministic and offline. AI-assisted explanations remain a future optional layer and will never determine policy or exit codes.

### Audit authorization evidence

Create an evidence document using [`examples/authorization-lab/secure.json`](examples/authorization-lab/secure.json) as the schema, then run:

```bash
mcp-guardian audit-auth authorization-evidence.json --fail-on high
mcp-guardian audit-auth authorization-evidence.json --format json
```

The auditor validates RFC 9728 Protected Resource Metadata, authorization-server issuer binding, HTTPS endpoints, PKCE `S256`, canonical resource indicators, audience validation evidence, redirect URI safety, registration mechanisms, token passthrough, mix-up protection, CORS, host allowlists, rate limiting, and secret-safe logging guidance.

It is deliberately passive: it does not request authorization codes, create clients, submit tokens, or probe authenticated endpoints. Boolean policy fields are implementation evidence supplied by the operator and should be backed by configuration or tests.

### Run the policy gateway

Start a configured stdio server behind Guardian using the example policy as a template:

```bash
mcp-guardian gateway .mcp.json \
  --server filesystem \
  --policy examples/gateway/policy.json \
  --allow-process \
  --audit .mcp-guardian-audit.jsonl
```

The gateway defaults to deny, intercepts `tools/call`, enforces tool actions, filesystem roots, network hosts, per-minute request limits, request/response sizes, and response timeouts. `approval` rules currently stop execution with JSON-RPC error `-32001`; a secure one-time approval continuation flow remains on the roadmap.

Audit events contain server/tool names, policy decisions, argument hashes, and a SHA-256 hash chain. Raw arguments, tokens, and secret values are never written to the audit file.

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
| `MCG201` | High | Instruction-like tool poisoning text |
| `MCG202` | Medium–High | Duplicate or conflicting tool names across servers |
| `MCG203` | Medium | Invisible or bidirectional Unicode controls |
| `MCG204` | Medium | Encoded instruction-like content |
| `MCG205` | Medium–High | Cross-server invocation or risky data-flow capabilities |
| `MCG206` | Medium | Tool schema and annotation inconsistencies |

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

A reusable standalone action is available at [`hanzales/mcp-guardian-action`](https://github.com/hanzales/mcp-guardian-action):

```yaml
name: MCP security

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hanzales/mcp-guardian-action@v1
        with:
          config: .mcp.json
          version: 0.6.0-preview.2
          fail-on: high
          format: sarif
          output: artifacts/mcp-guardian.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: artifacts/mcp-guardian.sarif
```

The action downloads a pinned self-contained release binary and supports Linux x64, macOS x64/arm64, and Windows x64 runners. It does not execute MCP servers or advertised tools.

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

The next milestones include secure approval continuation, a reusable GitHub
Action, signed release binaries, and an MCP interface for Guardian's safe
analysis tools. See [ROADMAP.md](ROADMAP.md).

## Responsible disclosure

Do not open public issues for suspected vulnerabilities. Follow [SECURITY.md](SECURITY.md) to report them privately.

## License

[MIT](LICENSE)
