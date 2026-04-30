from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import signal
import sys
import time
from typing import Any

from .policy import inspect_mcp, normalize_policy


BLOCK_ERROR_CODE = -32080


def _load_policy_config(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_stderr(message: str):
    sys.stderr.write(f"{message}\n")
    sys.stderr.flush()


def _json_dumps(message: dict[str, Any]) -> str:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"))


def _jsonrpc_error(*, request_id: Any, message: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": BLOCK_ERROR_CODE,
            "message": message,
            "data": {
                "veil": {
                    "action": result["action"],
                    "summary": result["summary"],
                    "findings": result["findings"],
                }
            },
        },
    }


def _infer_declared_access(tool: dict[str, Any]) -> str | None:
    annotations = tool.get("annotations")
    if not isinstance(annotations, dict):
        return None
    if annotations.get("readOnlyHint") is True:
        return "read"
    if annotations.get("destructiveHint") is True:
        return "write"
    return None


class MCPProxy:
    def __init__(
        self,
        *,
        server_name: str,
        policy: str,
        policy_config: dict[str, Any] | None,
        audit_log_path: str | None,
        redact_audit_payloads: bool,
        filter_descriptors: bool,
    ):
        self.server_name = server_name
        self.policy = normalize_policy(policy)
        self.policy_config = policy_config
        self.audit_log_path = audit_log_path
        self.redact_audit_payloads = redact_audit_payloads
        self.filter_descriptors = filter_descriptors
        self.pending_requests: dict[Any, dict[str, Any]] = {}

    def audit(
        self,
        *,
        stage: str,
        tool_name: str,
        result: dict[str, Any],
        blocked: bool,
        payload: Any = None,
    ):
        entry = {
            "timestamp": time.time(),
            "server_name": self.server_name,
            "tool_name": tool_name,
            "stage": stage,
            "action": result["action"],
            "blocked": blocked,
            "risk_score": result.get("summary", {}).get("risk_score", 0),
            "findings_count": len(result.get("findings", [])),
            "finding_types": sorted({f"{item['type']}:{item['subtype']}" for item in result.get("findings", [])}),
        }
        if not self.redact_audit_payloads:
            entry["payload"] = payload

        if self.audit_log_path:
            with open(self.audit_log_path, "a", encoding="utf-8") as handle:
                handle.write(_json_dumps(entry) + "\n")

        if blocked:
            finding_types = ", ".join(entry["finding_types"]) or "no findings"
            _write_stderr(f"[veil-mcp] blocked {stage} {self.server_name}.{tool_name}: {finding_types}")

    def inspect_call(self, message: dict[str, Any]) -> dict[str, Any] | None:
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        tool_name = str(params.get("name", "")).strip()
        if not tool_name:
            return None

        payload = params.get("arguments", {})
        result = inspect_mcp(
            stage="call",
            server_name=self.server_name,
            tool_name=tool_name,
            payload=payload,
            policy=self.policy,
            policy_config=self.policy_config,
        )
        blocked = result["action"] == "block"
        self.audit(stage="call", tool_name=tool_name, result=result, blocked=blocked, payload=payload)
        if not blocked:
            return None
        return _jsonrpc_error(
            request_id=message.get("id"),
            message=f"Veil blocked MCP tool call: {self.server_name}.{tool_name}",
            result=result,
        )

    def inspect_tools_list_response(self, message: dict[str, Any]) -> dict[str, Any]:
        result = message.get("result")
        if not isinstance(result, dict):
            return message
        tools = result.get("tools")
        if not isinstance(tools, list):
            return message

        filtered_tools = []
        removed = []
        for tool in tools:
            if not isinstance(tool, dict):
                filtered_tools.append(tool)
                continue

            tool_name = str(tool.get("name", "")).strip()
            descriptor_result = inspect_mcp(
                stage="descriptor",
                server_name=self.server_name,
                tool_name=tool_name,
                description=str(tool.get("description", "")),
                input_schema=tool.get("inputSchema"),
                declared_access=_infer_declared_access(tool),
                policy=self.policy,
                policy_config=self.policy_config,
            )
            blocked = descriptor_result["action"] == "block"
            self.audit(
                stage="descriptor",
                tool_name=tool_name,
                result=descriptor_result,
                blocked=blocked,
                payload=tool,
            )
            if blocked and self.filter_descriptors:
                removed.append(tool_name)
                continue
            filtered_tools.append(tool)

        if not removed:
            return message

        updated = copy.deepcopy(message)
        updated["result"]["tools"] = filtered_tools
        return updated

    def inspect_call_response(self, message: dict[str, Any], pending: dict[str, Any]) -> dict[str, Any]:
        if "result" not in message:
            return message
        tool_name = pending.get("tool_name", "unknown")
        payload = message.get("result")
        result = inspect_mcp(
            stage="result",
            server_name=self.server_name,
            tool_name=tool_name,
            payload=payload,
            policy=self.policy,
            policy_config=self.policy_config,
        )
        blocked = result["action"] == "block"
        self.audit(stage="result", tool_name=tool_name, result=result, blocked=blocked, payload=payload)
        if not blocked:
            return message
        return _jsonrpc_error(
            request_id=message.get("id"),
            message=f"Veil blocked MCP tool result: {self.server_name}.{tool_name}",
            result=result,
        )

    async def handle_client_message(self, message: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        method = message.get("method")
        request_id = message.get("id")

        if request_id is not None and method:
            pending = {"method": method}
            if method == "tools/call":
                params = message.get("params") if isinstance(message.get("params"), dict) else {}
                pending["tool_name"] = str(params.get("name", "")).strip()
            self.pending_requests[request_id] = pending

        if method == "tools/call":
            blocked_response = self.inspect_call(message)
            if blocked_response is not None:
                if request_id is not None:
                    self.pending_requests.pop(request_id, None)
                    return blocked_response, False
                return message, False

        return message, True

    async def handle_server_message(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = message.get("id")
        pending = self.pending_requests.pop(request_id, None) if request_id is not None else None
        if not pending:
            return message

        if pending.get("method") == "tools/list":
            return self.inspect_tools_list_response(message)
        if pending.get("method") == "tools/call":
            return self.inspect_call_response(message, pending)
        return message


async def _forward_stderr(process: asyncio.subprocess.Process):
    assert process.stderr is not None
    while True:
        line = await process.stderr.readline()
        if not line:
            break
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()


async def _client_to_server(proxy: MCPProxy, process: asyncio.subprocess.Process):
    assert process.stdin is not None
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
        if not line:
            break
        if not line.strip():
            continue

        try:
            message = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            _write_stderr("[veil-mcp] dropping malformed client JSON-RPC message")
            continue

        outbound, should_forward = await proxy.handle_client_message(message)
        if should_forward:
            process.stdin.write((_json_dumps(outbound) + "\n").encode("utf-8"))
            await process.stdin.drain()
        else:
            sys.stdout.write(_json_dumps(outbound) + "\n")
            sys.stdout.flush()

    try:
        process.stdin.close()
        await process.stdin.wait_closed()
    except Exception:
        pass


async def _server_to_client(proxy: MCPProxy, process: asyncio.subprocess.Process):
    assert process.stdout is not None
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        if not line.strip():
            continue

        try:
            message = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            _write_stderr("[veil-mcp] dropping malformed upstream JSON-RPC message")
            continue

        outbound = await proxy.handle_server_message(message)
        sys.stdout.write(_json_dumps(outbound) + "\n")
        sys.stdout.flush()


async def _run(args: argparse.Namespace) -> int:
    policy_config = _load_policy_config(args.policy_config)
    proxy = MCPProxy(
        server_name=args.server_name,
        policy=args.policy,
        policy_config=policy_config,
        audit_log_path=args.audit_log,
        redact_audit_payloads=not args.audit_payloads,
        filter_descriptors=not args.no_filter_descriptors,
    )

    process = await asyncio.create_subprocess_exec(
        *args.command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )

    if sys.platform != "win32":
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, process.terminate)

    tasks = [
        asyncio.create_task(_client_to_server(proxy, process)),
        asyncio.create_task(_server_to_client(proxy, process)),
        asyncio.create_task(_forward_stderr(process)),
    ]

    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            exc = task.exception()
            if exc:
                raise exc
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return await process.wait()
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil-mcp-proxy",
        description="Run an MCP stdio server behind Veil policy enforcement.",
    )
    parser.add_argument("--server-name", required=True, help="Logical MCP server name used for policy matching.")
    parser.add_argument("--policy", default="block", choices=["off", "monitor", "block"], help="Firewall policy action.")
    parser.add_argument("--policy-config", help="Path to a JSON MCP policy pack.")
    parser.add_argument("--audit-log", help="Append JSONL audit events to this file.")
    parser.add_argument("--audit-payloads", action="store_true", help="Include raw MCP payloads in the audit log.")
    parser.add_argument(
        "--no-filter-descriptors",
        action="store_true",
        help="Do not remove blocked tools from tools/list responses.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Upstream MCP server command after --.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("upstream MCP server command is required after --")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
