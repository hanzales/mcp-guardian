# Roadmap

The roadmap is ordered by security value and implementation dependency. Versions are targets, not guarantees.

## v0.2 — Configuration trust foundation

- [x] .NET 10 migration
- [x] Supported client configuration discovery
- [x] Text, JSON, and SARIF reports
- [x] Severity-based CI policy gate
- [x] Canonical configuration fingerprints
- [x] Baseline drift detection
- [x] .NET tool packaging

## v0.3 — Live capability inspector

- [x] Explicit, opt-in stdio server inspection
- [x] Streamable HTTP inspection
- [x] Protocol version and capability inventory
- [x] `tools/list`, resources, and prompts export
- [x] Tool-schema fingerprints
- [x] Added, removed, and modified tool detection
- [x] Strict timeouts, response limits, and process cleanup

## v0.4 — Semantic attack-surface analysis

- [x] Deterministic tool-poisoning patterns
- [x] Tool shadowing and cross-server escalation indicators
- [x] Suspicious Unicode and encoded instruction detection
- [x] Annotation/schema consistency checks
- [ ] Optional AI-assisted explanation that never makes enforcement decisions
- [x] MCP Security Lab fixtures and regression suite

## v0.5 — Authorization auditor

- [ ] Protected Resource Metadata and Authorization Server Metadata validation
- [ ] PKCE `S256`, resource indicator, token audience, and issuer checks
- [ ] Redirect URI and Dynamic Client Registration checks
- [ ] Token-passthrough and confused-deputy diagnostics
- [ ] CORS, allowed-host, rate-limit, and logging guidance

## v1.0 — Runtime policy gateway

- [ ] Per-server and per-tool allow/deny policies
- [ ] Argument and filesystem path constraints
- [ ] Approval gates for sensitive operations
- [ ] Secret redaction and tamper-evident audit events
- [ ] Network destination allowlists
- [ ] Rate, timeout, request-size, and response-size limits
- [ ] Reusable GitHub Action and signed release binaries
- [ ] MCP server interface for Guardian's safe analysis tools

## Design commitments

- Static scanning remains deterministic and side-effect free.
- Language models may explain findings but never enforce policy.
- New rules require vulnerable and safe regression fixtures.
- Security-sensitive defaults favor least privilege.
- Reports must not expose detected secret values.
