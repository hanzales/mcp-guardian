# Architecture

MCP Guardian `0.6` is a dependency-free .NET 10 command-line application. Static, semantic, and authorization evidence analysis are deterministic. The runtime gateway applies deterministic policy before forwarding stdio MCP calls.

## Components

```text
CLI
├── Discovery ── finds supported client configuration files
├── Scanner ──── evaluates deterministic security rules
├── Baselines ── canonicalizes and fingerprints server definitions
├── Inspection ─ negotiates bounded stdio or Streamable HTTP sessions
├── Capabilities exports metadata and fingerprints tool definitions
├── Semantics ── detects metadata attacks and cross-server composition risks
├── Authorization validates OAuth metadata and implementation evidence
├── Gateway ───── enforces runtime tool, argument, destination, and limit policy
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

### Semantic analysis

`SemanticAnalyzer` treats every server-provided name, description, schema, and annotation as untrusted data. It applies bounded regular expressions and structural JSON checks, decodes only constrained base64 candidates, and emits findings that identify the affected tool without repeating the matched instruction. Multi-report analysis compares tool ownership and detects both explicit cross-server invocation text and source-to-sink capability composition. Input is capped at 64 reports, 10,000 tools, and 10 MiB per report.

The analyzer does not execute metadata, invoke tools, reconnect to servers, or make AI calls. Its findings alone determine `--fail-on`; any future AI explanation layer must consume already-sanitized findings and cannot change severity, policy, or exit status.

### Authorization auditing

`AuthorizationAuditor` validates RFC 9728 resource metadata and RFC 8414/OIDC authorization-server metadata alongside an explicit evidence contract. Metadata checks are direct; behavioral fields such as audience validation and token forwarding are operator assertions intended to be backed by configuration review or integration tests. The auditor never handles credentials or runs an OAuth flow, preventing an audit from creating clients, issuing tokens, or changing external state.

### Runtime gateway

`PolicyEngine` is default-deny and evaluates server/tool action, path roots, network destinations, and a sliding request-rate window. `StdioGateway` launches the configured executable directly, forwards JSON-RPC messages, blocks denied calls locally, and bounds requests, responses, and response time. `AuditChainWriter` omits raw arguments, records their SHA-256 hash, and links each event to the previous hash so later edits are detectable.

The initial gateway is intentionally limited to sequential stdio traffic. Approval policies fail closed but do not yet provide a continuation token. Streamable HTTP proxying, concurrent request multiplexing, cryptographically keyed audit checkpoints, and interactive one-time approval remain future work.

## Trust boundaries

Guardian treats configuration files, server names, commands, arguments, URLs, environment variables, and baseline files as untrusted input.

The `scan`, `discover`, and configuration `baseline` commands do not execute commands, connect to servers, resolve packages, interpolate environment variables, or follow URLs. This keeps configuration scanning side-effect free.

The `inspect` command crosses a separate runtime trust boundary. Stdio inspection requires `--allow-process`; HTTP inspection is explicit by command selection. Guardian never invokes listed tools, reads listed resources, or renders listed prompts. Time and byte limits reduce denial-of-service exposure but do not replace OS sandboxing, network isolation, or least-privilege credentials.

## Privacy

Secret values are never copied into findings. A hard-coded secret finding reports only the variable name. Baselines contain hashes rather than raw configuration. JSON and text reports contain the scanned target path; avoid publishing reports from user-level configurations if the local path itself is sensitive.

## Future boundaries

Semantic analysis, authorization auditing, and the runtime policy gateway will remain separate from static scanning and capability inventory. Static `scan` must remain side-effect free, while future enforcement must keep deterministic decisions outside language models.
