# Veil MCP

[![CI](https://github.com/Atomics-hub/veil-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Atomics-hub/veil-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Atomics-hub/veil-mcp)](https://github.com/Atomics-hub/veil-mcp/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Veil MCP is a local firewall for Model Context Protocol servers. It sits between an AI client and an MCP stdio server, inspects tool descriptors, tool-call arguments, and tool results, then blocks risky activity before it reaches the model or the tool.

It is built for the practical mess of agent work: poisoned tool descriptions, secret-file reads, webhook exfiltration, surprise write tools, and MCP servers that quietly expose more power than you meant to give them.

![Veil MCP terminal demo](https://raw.githubusercontent.com/Atomics-hub/veil-mcp/main/assets/veil-mcp-demo.gif)

## Why This Exists

MCP makes AI agents useful because it gives them tools. That also means one bad server, one compromised package, or one prompt-injected tool result can turn into file reads, secret leakage, data exfiltration, or destructive actions.

Veil MCP gives teams a small, local, auditable control layer:

- Filter dangerous tools from `tools/list`.
- Block unsafe `tools/call` requests before they hit the server.
- Inspect tool results for secrets and prompt-injection payloads before the model sees them.
- Enforce allowlists for servers, tools, paths, and domains.
- Write compact JSONL audit logs for incident review.

## Quick Start

From this repo:

```bash
python -m pip install -e .
python scripts/smoke_mcp_proxy.py --show-stderr
```

Expected smoke-test shape:

```text
PASS initialize passes through
PASS tools/list filters poisoned tools
PASS safe read_file call passes
PASS secret file call is blocked
PASS blocked call includes Veil findings
PASS exfiltration tool call is blocked
PASS audit log written
PASS audit log records blocks

Veil MCP proxy smoke demo passed.
```

## Run A Server Behind Veil

Use `veil-mcp-proxy` as the command your AI client launches. Put the upstream MCP server command after `--`.

```bash
veil-mcp-proxy \
  --server-name filesystem \
  --policy block \
  --policy-config policies/mcp-local-dev.json \
  --audit-log veil-mcp-audit.jsonl \
  -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

Policies support three modes:

- `block`: allow clean traffic and block high-confidence high-risk findings.
- `monitor`: log findings, but allow traffic.
- `off`: proxy traffic without enforcement.

By default, audit logs redact raw payloads. Add `--audit-payloads` only when you are intentionally collecting full MCP request and result bodies.

## Client Config Examples

The `configs/` directory contains before-and-after examples for common MCP clients:

- `configs/claude-desktop-unsafe.json`
- `configs/claude-desktop-veil.json`
- `configs/cursor-mcp-unsafe.json`
- `configs/cursor-mcp-veil.json`

Update `/absolute/path/to/veil-mcp` to this repo path before using those examples.

## Policy Pack

A policy pack is a JSON object. Globs are case-insensitive. Tool identifiers can match either `server.tool`, `tool`, or `server`.

```json
{
  "allowed_servers": ["filesystem", "github"],
  "blocked_servers": ["unknown-*"],
  "allowed_tools": ["filesystem.read_file", "github.get_*"],
  "blocked_tools": ["*.write_file", "*.delete_*"],
  "read_only_servers": ["filesystem"],
  "read_only_tools": ["github.get_*"],
  "require_approval_tools": ["github.create_issue"],
  "allowed_paths": ["./docs/**", "/tmp/safe/**"],
  "blocked_paths": ["**/.env*", "**/.ssh/**"],
  "allowed_domains": ["api.github.com"],
  "blocked_domains": ["webhook.site", "*.ngrok-free.app"]
}
```

Important fields:

| Field | Meaning |
| --- | --- |
| `allowed_servers` | Only these MCP servers may be used. |
| `blocked_servers` | These MCP servers are always blocked. |
| `allowed_tools` | Only these tools may appear or be called. |
| `blocked_tools` | These tools are always blocked. |
| `read_only_servers` | Blocks mutating call arguments for matching servers. |
| `read_only_tools` | Blocks mutating call arguments for matching tools. |
| `require_approval_tools` | Treats matching tool calls as blocked pending human approval. |
| `allowed_paths` | Only these paths may appear in calls and results. |
| `blocked_paths` | These paths are always blocked. |
| `allowed_domains` | Only these domains may appear in calls and results. |
| `blocked_domains` | These domains are always blocked. |

## What Veil Detects

Veil MCP ships with local heuristic checks for:

- Prompt-injection instructions in tool descriptions, arguments, and results.
- Attempts to reveal system prompts, hidden instructions, or credentials.
- Tool poisoning phrases such as forced or mandatory tool use.
- Secret patterns including AWS keys, GitHub tokens, Stripe keys, OpenAI-style keys, database URLs, private keys, and bearer tokens.
- Risky links such as URL shorteners, tunnels, localhost URLs, and raw IP URLs.
- Sensitive paths such as `.env`, `.ssh`, cloud credential folders, private keys, and system files.
- Destructive or mutating action language in read-only contexts.

## Block Response

When Veil blocks a request or result, the client receives a JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "error": {
    "code": -32080,
    "message": "Veil blocked MCP tool call: demo.read_file",
    "data": {
      "veil": {
        "action": "block",
        "summary": {
          "total_findings": 2,
          "blocked": true
        },
        "findings": []
      }
    }
  }
}
```

The actual `findings` array includes typed reasons, severities, confidence scores, stages, and short snippets.

## Security Model

Veil MCP is a local stdio proxy. It does not phone home, require a hosted service, or send traffic to an external model. It is meant to be one layer in a defense-in-depth setup:

- Keep MCP servers pinned and reviewed.
- Prefer least-privilege policy packs per project.
- Run write-capable servers separately from read-only servers.
- Keep raw audit payloads disabled unless you have a retention plan.
- Treat `monitor` mode as a rollout mode, not a final safety posture.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests
python scripts/smoke_mcp_proxy.py
```

The demo server in `demos/malicious_mcp_server.py` intentionally exposes unsafe tools so the smoke test can prove descriptor filtering, call blocking, result inspection, and audit logging.
