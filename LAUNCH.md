# Launch Kit

## One-Liner

Veil MCP is a local firewall for AI agent tools: block poisoned MCP tool descriptions, secret-file reads, webhook exfiltration, unsafe tool results, and overbroad servers before they reach your agent.

## Short Post

MCP makes AI agents useful by giving them tools. That also creates a new security boundary: tool descriptions can be poisoned, tool calls can overreach, and tool results can leak secrets or inject instructions back into the model.

Veil MCP is an open-source local stdio proxy that sits between your MCP client and server. It filters risky tools from `tools/list`, blocks unsafe `tools/call` requests, inspects results before the model sees them, and writes compact JSONL audit logs.

Repo: https://github.com/Atomics-hub/veil-mcp

## Show HN Draft

Title: Show HN: Veil MCP, a local firewall for AI agent tool calls

Body:

I built Veil MCP after looking at how quickly local agent setups are adding MCP servers for filesystems, GitHub, browsers, terminals, and internal tools.

MCP is useful because it gives agents tools, but that also means tool descriptions, call arguments, and tool results become a security boundary. Veil MCP is a local stdio proxy that can:

- filter poisoned or overbroad tools from `tools/list`
- block risky `tools/call` requests before they reach the server
- inspect tool results for secrets and prompt injection before the model sees them
- enforce allowlists for servers, tools, paths, and domains
- write JSONL audit logs locally

It ships with a malicious demo MCP server and smoke test so the failure modes are easy to see.

Repo: https://github.com/Atomics-hub/veil-mcp

## Demo Commands

```bash
git clone https://github.com/Atomics-hub/veil-mcp
cd veil-mcp
python -m pip install -e .
python scripts/smoke_mcp_proxy.py --show-stderr
```

