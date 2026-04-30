# Security Policy

## Supported Versions

This project is pre-1.0. Security fixes are currently shipped on the latest `main` branch and in the newest package release.

## Reporting A Vulnerability

Please open a private security advisory on GitHub when the public repository is live. Include:

- Affected version or commit.
- MCP server/client configuration.
- Minimal JSON-RPC request or tool descriptor that reproduces the issue.
- Expected and actual Veil behavior.

Do not include real secrets, private prompts, or customer data in reports.

## Scope

In scope:

- Policy bypasses that allow high-risk MCP tool calls or results.
- Audit log leakage when payload redaction is enabled.
- Crashes triggered by malformed but plausible MCP JSON-RPC messages.

Out of scope:

- Findings that require intentionally disabling enforcement with `--policy off`.
- Secrets intentionally included when `--audit-payloads` is enabled.
- Vulnerabilities in upstream MCP servers that Veil is proxying.

