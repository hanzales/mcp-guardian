# Architecture

MCP Guardian `0.2` is a dependency-free .NET 10 command-line application. The implementation is deterministic: the same configuration produces the same findings and server fingerprints regardless of model availability.

## Components

```text
CLI
├── Discovery ── finds supported client configuration files
├── Scanner ──── evaluates deterministic security rules
├── Baselines ── canonicalizes and fingerprints server definitions
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

## Trust boundaries

Guardian treats configuration files, server names, commands, arguments, URLs, environment variables, and baseline files as untrusted input.

The scanner does not execute commands, connect to servers, resolve packages, interpolate environment variables, or follow URLs. This keeps configuration scanning side-effect free.

## Privacy

Secret values are never copied into findings. A hard-coded secret finding reports only the variable name. Baselines contain hashes rather than raw configuration. JSON and text reports contain the scanned target path; avoid publishing reports from user-level configurations if the local path itself is sensitive.

## Future boundaries

Live inspection and the runtime gateway will be isolated from static scanning. They will require explicit commands, bounded timeouts, output limits, transport allowlists, and separate threat models. Static `scan` must remain side-effect free.
