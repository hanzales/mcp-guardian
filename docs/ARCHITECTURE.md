# Architecture

MCP Guardian `0.3` is a dependency-free .NET 10 command-line application. Static analysis is deterministic: the same configuration produces the same findings and server fingerprints regardless of model availability. Live inspection is isolated behind an explicit command and records server-provided state.

## Components

```text
CLI
├── Discovery ── finds supported client configuration files
├── Scanner ──── evaluates deterministic security rules
├── Baselines ── canonicalizes and fingerprints server definitions
├── Inspection ─ negotiates bounded stdio or Streamable HTTP sessions
├── Capabilities exports metadata and fingerprints tool definitions
└── Reporters ── writes text, JSON, or SARIF
```

### Discovery

`ConfigDiscovery` checks a fixed set of documented project and user paths. It does not recursively search the entire home directory, read file contents, start servers, or change configurations.

### Scanner

`ConfigScanner` parses JSON with comments and trailing commas enabled, locates the `mcpServers` object, and evaluates every server definition. Findings contain stable rule IDs, severity, server name, explanation, and remediation.

### Baselines

`ConfigBaselineService` recursively sorts JSON object properties while preserving array order, serializes the canonical representation, and computes a SHA-256 fingerprint for each server. The baseline stores only hashes and metadata—not commands, arguments, URLs, environment values, or secrets.

Baseline verification uses fixed-time hash comparison and reports additions, removals, and modifications.

### Reporting

- Text is optimized for local review.
- JSON preserves the internal report contract.
- SARIF 2.1.0 maps high and critical findings to `error`, medium to `warning`, and lower severities to `note`.

### Live inspection

`ServerConfigReader` selects one named server without interpolating configuration values. `StdioMcpTransport` starts the configured executable directly without a shell, exchanges newline-delimited JSON-RPC messages, drains stderr without retaining it, and kills the complete process tree during cleanup. `HttpMcpTransport` sends MCP POST requests, accepts JSON or SSE responses, preserves the negotiated session ID and protocol version, and disables redirects.

`CapabilityInspector` performs `initialize`, sends `notifications/initialized`, and follows advertised `tools/list`, `resources/list`, and `prompts/list` pagination. Each response has a byte limit and timeout, and each list has a 100-page limit. Tool definitions are canonicalized with sorted object keys and fingerprinted with SHA-256. `CapabilityBaselineService` compares fingerprints in fixed time and reports added, removed, and modified tools.

## Trust boundaries

Guardian treats configuration files, server names, commands, arguments, URLs, environment variables, and baseline files as untrusted input.

The `scan`, `discover`, and configuration `baseline` commands do not execute commands, connect to servers, resolve packages, interpolate environment variables, or follow URLs. This keeps configuration scanning side-effect free.

The `inspect` command crosses a separate runtime trust boundary. Stdio inspection requires `--allow-process`; HTTP inspection is explicit by command selection. Guardian never invokes listed tools, reads listed resources, or renders listed prompts. Time and byte limits reduce denial-of-service exposure but do not replace OS sandboxing, network isolation, or least-privilege credentials.

## Privacy

Secret values are never copied into findings. A hard-coded secret finding reports only the variable name. Baselines contain hashes rather than raw configuration. JSON and text reports contain the scanned target path; avoid publishing reports from user-level configurations if the local path itself is sensitive.

## Future boundaries

Semantic analysis, authorization auditing, and the runtime policy gateway will remain separate from static scanning and capability inventory. Static `scan` must remain side-effect free, while future enforcement must keep deterministic decisions outside language models.
