from __future__ import annotations

import fnmatch
import json
import re
from typing import Any
from urllib.parse import urlparse


SEVERITY_SCORES = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

PROMPT_INJECTION_PATTERNS = [
    {
        "type": "prompt_injection",
        "subtype": "instruction_override",
        "severity": "high",
        "confidence": 0.86,
        "regex": re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b.{0,50}\b(?:previous|earlier|prior|system|developer|safety|guardrail|instructions?)\b"
        ),
    },
    {
        "type": "prompt_injection",
        "subtype": "system_prompt_extraction",
        "severity": "high",
        "confidence": 0.9,
        "regex": re.compile(
            r"(?i)\b(?:reveal|print|show|repeat|dump|leak|expose)\b.{0,40}\b(?:system prompt|developer message|internal instructions?|hidden prompt|chain of thought)\b"
        ),
    },
    {
        "type": "prompt_injection",
        "subtype": "data_exfiltration",
        "severity": "critical",
        "confidence": 0.88,
        "regex": re.compile(
            r"(?i)\b(?:send|post|upload|exfiltrate|forward|email|webhook|curl|fetch)\b.{0,70}\b(?:secret|token|password|credential|data|context|prompt|instructions?)\b"
        ),
    },
    {
        "type": "prompt_injection",
        "subtype": "credential_harvesting",
        "severity": "critical",
        "confidence": 0.91,
        "regex": re.compile(
            r"(?i)\b(?:api[-_\s]?key|token|password|credential|secret|bearer)\b.{0,40}\b(?:reveal|return|show|print|send|share|expose)\b|"
            r"\b(?:reveal|return|show|print|send|share|expose)\b.{0,40}\b(?:api[-_\s]?key|token|password|credential|secret|bearer)\b"
        ),
    },
    {
        "type": "prompt_injection",
        "subtype": "tool_misuse",
        "severity": "high",
        "confidence": 0.83,
        "regex": re.compile(
            r"(?i)\b(?:call|use|invoke|run|open|execute)\b.{0,60}\b(?:filesystem|terminal|shell|browser|email|payment|github|git|delete|rm\b|drop table|ssh)\b"
        ),
    },
    {
        "type": "prompt_injection",
        "subtype": "approval_bypass",
        "severity": "high",
        "confidence": 0.84,
        "regex": re.compile(
            r"(?i)\b(?:without|skip|ignore|bypass)\b.{0,35}\b(?:approval|confirmation|consent|review|permission)\b|"
            r"\b(?:do not|don't)\b.{0,20}\b(?:ask|warn|mention|confirm)\b"
        ),
    },
    {
        "type": "prompt_injection",
        "subtype": "hidden_instruction",
        "severity": "medium",
        "confidence": 0.72,
        "regex": re.compile(
            r"(?i)(?:<!--|BEGIN (?:SYSTEM|PROMPT)|END (?:SYSTEM|PROMPT)|hidden instruction|invisible instruction|ignore this notice)"
        ),
    },
]

OUTPUT_POLICY_PATTERNS = [
    {
        "type": "output_filter",
        "subtype": "prompt_leakage",
        "severity": "high",
        "confidence": 0.84,
        "regex": re.compile(
            r"(?i)\b(?:system prompt|developer message|internal instruction|hidden rules|confidential prompt|policy text)\b"
        ),
    },
]

SECRET_PATTERNS = [
    {
        "type": "data_exposure",
        "subtype": "aws_access_key",
        "severity": "critical",
        "confidence": 0.95,
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "type": "data_exposure",
        "subtype": "github_token",
        "severity": "critical",
        "confidence": 0.95,
        "regex": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    },
    {
        "type": "data_exposure",
        "subtype": "stripe_key",
        "severity": "critical",
        "confidence": 0.95,
        "regex": re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    },
    {
        "type": "data_exposure",
        "subtype": "openai_key",
        "severity": "critical",
        "confidence": 0.92,
        "regex": re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    },
    {
        "type": "data_exposure",
        "subtype": "database_url",
        "severity": "critical",
        "confidence": 0.9,
        "regex": re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s\"'<>]+"),
    },
    {
        "type": "data_exposure",
        "subtype": "private_key",
        "severity": "critical",
        "confidence": 0.96,
        "regex": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    },
    {
        "type": "data_exposure",
        "subtype": "bearer_token",
        "severity": "critical",
        "confidence": 0.86,
        "regex": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{24,}"),
    },
]

DESTRUCTIVE_ACTION_PATTERN = re.compile(
    r"(?i)\b(?:delete|destroy|wipe|shutdown|terminate|drop table|rm\s+-rf|chmod\s+777|curl\b.+\|\s*sh|sudo\b|exfiltrate|send to)\b"
)

MUTATING_ACTION_PATTERN = re.compile(
    r"(?i)\b(?:create|update|delete|destroy|write|append|modify|patch|post|put|send|commit|push|merge|deploy|execute|run|shell|chmod|chown|rm\s+-rf|drop table|truncate)\b"
)

URL_PATTERN = re.compile(r"https?://[^\s)>\]}]+")
URI_PATTERN = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s)>\]}]+", re.IGNORECASE)

PATH_PATTERN = re.compile(
    r"(?P<path>(?:~|[A-Za-z]:)?[/\\][^\s\"'<>`{}]+|(?:\.\.?[/\\])[^\s\"'<>`{}]+)"
)

DEFAULT_SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(?i)(?:^|[^A-Za-z0-9_.-])(?:\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|\.pypirc|id_rsa|id_ed25519|known_hosts)(?:$|[^A-Za-z0-9_.-])"),
    re.compile(r"(?i)(?:^|[/\\])(?:\.ssh|\.aws|\.config[/\\]gcloud|Library[/\\]Keychains)(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[/\\])(?:secrets?|credentials?)(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[^A-Za-z0-9_.-])(?:secrets?|credentials?|service[-_]?account|private[-_]?key)[^\s\"'<>`{}]*(?:\.json|\.yaml|\.yml|\.pem|\.key)(?:$|[^A-Za-z0-9_.-])"),
    re.compile(r"(?i)(?:^|[/\\])etc[/\\](?:passwd|shadow|sudoers)(?:$|[^A-Za-z0-9_.-])"),
]

SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "tiny.one",
    "shorturl.at",
    "ngrok.io",
    "ngrok-free.app",
    "transfer.sh",
    "pastebin.com",
    "gist.githubusercontent.com",
}

DEFAULT_BLOCKED_DOMAINS = {
    "webhook.site",
    "requestbin.com",
    "pipedream.net",
    "ngrok.io",
    "ngrok-free.app",
    "localtunnel.me",
    "transfer.sh",
    "pastebin.com",
}


def normalize_policy(policy: str | None, default: str = "block") -> str:
    value = (policy or default).strip().lower()
    if value not in {"off", "monitor", "block"}:
        raise ValueError("policy must be one of: off, monitor, block")
    return value


def payload_to_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _snippet_from_text(text: str, start: int | None = None, end: int | None = None) -> str:
    if start is None or end is None:
        snippet = text[:180]
        return snippet if len(text) <= 180 else f"{snippet}..."
    left = max(0, start - 40)
    right = min(len(text), end + 40)
    snippet = text[left:right]
    return snippet if len(snippet) <= 180 else f"{snippet[:177]}..."


def _finding(
    finding_type: str,
    subtype: str,
    severity: str,
    confidence: float,
    stage: str,
    snippet: str,
    start: int | None = None,
    end: int | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "type": finding_type,
        "subtype": subtype,
        "severity": severity,
        "confidence": round(float(confidence), 2),
        "snippet": snippet,
        "stage": stage,
    }
    if start is not None:
        item["start"] = start
    if end is not None:
        item["end"] = end
    return item


def _append_regex_findings(findings: list[dict[str, Any]], text: str, stage: str, patterns: list[dict[str, Any]]):
    for pattern in patterns:
        for match in pattern["regex"].finditer(text):
            findings.append(
                _finding(
                    pattern["type"],
                    pattern["subtype"],
                    pattern["severity"],
                    pattern["confidence"],
                    stage,
                    _snippet_from_text(text, match.start(), match.end()),
                    match.start(),
                    match.end(),
                )
            )


def _append_link_findings(findings: list[dict[str, Any]], text: str, stage: str):
    for match in URL_PATTERN.finditer(text):
        url = match.group(0)
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            continue

        subtype = None
        severity = "medium"
        confidence = 0.68

        if parsed.scheme != "https":
            subtype = "insecure_link"
        elif hostname in SHORTENER_HOSTS or hostname.endswith(".ngrok.io") or hostname.endswith(".ngrok-free.app"):
            subtype = "shortener_or_tunnel"
            severity = "high"
            confidence = 0.82
        elif hostname in {"localhost", "127.0.0.1"} or hostname.endswith(".local"):
            subtype = "local_link"
            severity = "high"
            confidence = 0.8
        elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
            subtype = "ip_link"
            severity = "high"
            confidence = 0.77

        if subtype:
            findings.append(
                _finding(
                    "link_risk",
                    subtype,
                    severity,
                    confidence,
                    stage,
                    url,
                    match.start(),
                    match.end(),
                )
            )


def _append_destructive_action_findings(findings: list[dict[str, Any]], text: str, stage: str, subtype: str):
    for match in DESTRUCTIVE_ACTION_PATTERN.finditer(text):
        findings.append(
            _finding(
                "unsafe_action",
                subtype,
                "high",
                0.82,
                stage,
                _snippet_from_text(text, match.start(), match.end()),
                match.start(),
                match.end(),
            )
        )


def _coerce_policy_list(policy_config: dict[str, Any] | None, key: str) -> list[str]:
    if not policy_config:
        return []
    value = policy_config.get(key)
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        raise ValueError(f"policy_config.{key} must be a string or list of strings")
    items = []
    for item in value:
        if item is None:
            continue
        text = str(item).strip()
        if text:
            items.append(text)
    return items


def _match_glob(value: str, patterns: list[str]) -> bool:
    value = value.lower()
    return any(fnmatch.fnmatchcase(value, pattern.lower()) for pattern in patterns)


def _match_mcp_identifier(patterns: list[str], server_name: str, tool_name: str) -> bool:
    server = server_name.lower()
    tool = tool_name.lower()
    full = f"{server}.{tool}"
    return any(
        fnmatch.fnmatchcase(candidate, pattern.lower())
        for pattern in patterns
        for candidate in (full, tool, server)
    )


def _host_matches(hostname: str, patterns: list[str]) -> bool:
    host = hostname.lower()
    for pattern in patterns:
        normalized = pattern.lower().strip()
        if not normalized:
            continue
        if normalized.startswith("*.") and (host == normalized[2:] or host.endswith(normalized[1:])):
            return True
        if host == normalized or host.endswith(f".{normalized}") or fnmatch.fnmatchcase(host, normalized):
            return True
    return False


def _extract_urls(text: str) -> list[tuple[str, str, int, int]]:
    urls = []
    for match in URL_PATTERN.finditer(text):
        url = match.group(0)
        hostname = (urlparse(url).hostname or "").lower()
        if hostname:
            urls.append((url, hostname, match.start(), match.end()))
    return urls


def _flatten_strings(payload: Any) -> list[str]:
    values: list[str] = []
    if payload is None:
        return values
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, (int, float, bool)):
        return [str(payload)]
    if isinstance(payload, list):
        for item in payload:
            values.extend(_flatten_strings(item))
        return values
    if isinstance(payload, dict):
        for key, value in payload.items():
            values.append(str(key))
            values.extend(_flatten_strings(value))
        return values
    return [str(payload)]


def _extract_paths(payload: Any, text: str) -> list[str]:
    paths: list[str] = []
    for value in _flatten_strings(payload):
        trimmed = value.strip()
        if not trimmed:
            continue
        scrubbed = URI_PATTERN.sub(" ", trimmed)
        if not scrubbed.strip():
            continue
        if not re.search(r"\s", scrubbed) and ("/" in scrubbed or "\\" in scrubbed or scrubbed.startswith(".")):
            paths.append(scrubbed)
        for match in PATH_PATTERN.finditer(scrubbed):
            paths.append(match.group("path"))

    for match in PATH_PATTERN.finditer(URI_PATTERN.sub(" ", text)):
        paths.append(match.group("path"))

    seen = set()
    unique = []
    for path in paths:
        cleaned = path.strip().strip(".,;:)")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
    return unique


def _append_sensitive_path_findings(findings: list[dict[str, Any]], text: str, stage: str):
    for pattern in DEFAULT_SENSITIVE_PATH_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                _finding(
                    "mcp_policy",
                    "sensitive_path",
                    "critical",
                    0.89,
                    stage,
                    _snippet_from_text(text, match.start(), match.end()),
                    match.start(),
                    match.end(),
                )
            )


def _append_mcp_descriptor_findings(
    findings: list[dict[str, Any]],
    text: str,
    stage: str,
    declared_access: str | None,
):
    _append_regex_findings(findings, text, stage, PROMPT_INJECTION_PATTERNS)
    _append_regex_findings(findings, text, stage, SECRET_PATTERNS)

    if re.search(r"(?i)\balways\b.{0,25}\bcall\b|\bmust\b.{0,25}\buse this tool\b", text):
        findings.append(_finding("mcp_risk", "tool_poisoning", "high", 0.84, stage, _snippet_from_text(text)))

    if re.search(r"(?i)\b(fetch|load|pull)\b.{0,40}\b(?:instructions?|prompts?)\b.{0,20}\b(?:from|via)\b.{0,20}\b(?:https?://|url|remote)\b", text):
        findings.append(_finding("mcp_risk", "dynamic_instruction_source", "high", 0.8, stage, _snippet_from_text(text)))

    if declared_access == "read" and re.search(r"(?i)\b(create|update|delete|write|send|post|commit|push|execute|run)\b", text):
        findings.append(_finding("mcp_risk", "declared_access_mismatch", "high", 0.81, stage, _snippet_from_text(text)))
    if declared_access == "write" and re.search(r"(?i)\b(admin|sudo|root|billing|payment|permission|oauth scope|token rotation)\b", text):
        findings.append(_finding("mcp_risk", "scope_creep", "medium", 0.7, stage, _snippet_from_text(text)))


def _append_mcp_policy_findings(
    findings: list[dict[str, Any]],
    *,
    stage: str,
    server_name: str,
    tool_name: str,
    text: str,
    payload: Any,
    policy_config: dict[str, Any] | None,
):
    if policy_config is not None and not isinstance(policy_config, dict):
        raise ValueError("policy_config must be an object")

    blocked_servers = _coerce_policy_list(policy_config, "blocked_servers")
    allowed_servers = _coerce_policy_list(policy_config, "allowed_servers")
    blocked_tools = _coerce_policy_list(policy_config, "blocked_tools")
    allowed_tools = _coerce_policy_list(policy_config, "allowed_tools")
    read_only_servers = _coerce_policy_list(policy_config, "read_only_servers")
    read_only_tools = _coerce_policy_list(policy_config, "read_only_tools")
    approval_tools = _coerce_policy_list(policy_config, "require_approval_tools")
    blocked_domains = _coerce_policy_list(policy_config, "blocked_domains") or sorted(DEFAULT_BLOCKED_DOMAINS)
    allowed_domains = _coerce_policy_list(policy_config, "allowed_domains")
    blocked_paths = _coerce_policy_list(policy_config, "blocked_paths")
    allowed_paths = _coerce_policy_list(policy_config, "allowed_paths")

    if blocked_servers and _match_glob(server_name, blocked_servers):
        findings.append(_finding("mcp_policy", "server_blocked", "critical", 0.96, stage, server_name))
    if allowed_servers and not _match_glob(server_name, allowed_servers):
        findings.append(_finding("mcp_policy", "server_not_allowed", "high", 0.92, stage, server_name))
    if blocked_tools and _match_mcp_identifier(blocked_tools, server_name, tool_name):
        findings.append(_finding("mcp_policy", "tool_blocked", "critical", 0.96, stage, f"{server_name}.{tool_name}"))
    if allowed_tools and not _match_mcp_identifier(allowed_tools, server_name, tool_name):
        findings.append(_finding("mcp_policy", "tool_not_allowed", "high", 0.92, stage, f"{server_name}.{tool_name}"))

    is_call_stage = stage in {"call", "mcp_call"}

    if is_call_stage and approval_tools and _match_mcp_identifier(approval_tools, server_name, tool_name):
        findings.append(_finding("mcp_policy", "approval_required", "high", 0.9, stage, f"{server_name}.{tool_name}"))

    if is_call_stage and (
        _match_glob(server_name, read_only_servers) or _match_mcp_identifier(read_only_tools, server_name, tool_name)
    ) and MUTATING_ACTION_PATTERN.search(text):
        findings.append(_finding("mcp_policy", "read_only_violation", "high", 0.86, stage, _snippet_from_text(text)))

    for url, hostname, start, end in _extract_urls(text):
        if blocked_domains and _host_matches(hostname, blocked_domains):
            findings.append(_finding("mcp_policy", "domain_blocked", "critical", 0.93, stage, url, start, end))
        elif allowed_domains and not _host_matches(hostname, allowed_domains):
            findings.append(_finding("mcp_policy", "domain_not_allowed", "high", 0.88, stage, url, start, end))

    _append_sensitive_path_findings(findings, text, stage)

    for path in _extract_paths(payload, text):
        if blocked_paths and _match_glob(path, blocked_paths):
            findings.append(_finding("mcp_policy", "path_blocked", "critical", 0.94, stage, path))
        elif allowed_paths and not _match_glob(path, allowed_paths):
            findings.append(_finding("mcp_policy", "path_not_allowed", "high", 0.84, stage, path))


def _append_mcp_call_findings(findings: list[dict[str, Any]], text: str, stage: str):
    _append_regex_findings(findings, text, stage, PROMPT_INJECTION_PATTERNS)
    _append_regex_findings(findings, text, stage, SECRET_PATTERNS)
    _append_link_findings(findings, text, stage)
    _append_destructive_action_findings(findings, text, stage, "unsafe_tool_call_arguments")


def _append_mcp_result_findings(findings: list[dict[str, Any]], text: str, stage: str):
    _append_regex_findings(findings, text, stage, PROMPT_INJECTION_PATTERNS)
    _append_regex_findings(findings, text, stage, OUTPUT_POLICY_PATTERNS)
    _append_regex_findings(findings, text, stage, SECRET_PATTERNS)
    _append_link_findings(findings, text, stage)


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for finding in findings:
        key = (
            finding["type"],
            finding["subtype"],
            finding["severity"],
            finding.get("start"),
            finding.get("end"),
            finding["snippet"],
            finding["stage"],
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def summarize_findings(findings: list[dict[str, Any]], action: str) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_stage: dict[str, int] = {}
    blocked_candidates = 0
    for finding in findings:
        by_type[finding["type"]] = by_type.get(finding["type"], 0) + 1
        by_stage[finding["stage"]] = by_stage.get(finding["stage"], 0) + 1
        if SEVERITY_SCORES[finding["severity"]] >= 3 and finding["confidence"] >= 0.7:
            blocked_candidates += 1

    risk_score = 0
    if findings:
        risk_score = min(
            100,
            int(
                max(SEVERITY_SCORES[f["severity"]] * 20 + int(f["confidence"] * 10) for f in findings)
                + max(0, len(findings) - 1) * 5
            ),
        )

    return {
        "total_findings": len(findings),
        "blocked_candidates": blocked_candidates,
        "risk_score": risk_score,
        "blocked": action == "block",
        "by_type": by_type,
        "by_stage": by_stage,
    }


def resolve_action(findings: list[dict[str, Any]], policy: str) -> str:
    if policy in {"off", "monitor"}:
        return "allow"
    for finding in findings:
        if SEVERITY_SCORES[finding["severity"]] >= 3 and finding["confidence"] >= 0.7:
            return "block"
    return "allow"


def inspect_mcp(
    *,
    stage: str,
    server_name: str,
    tool_name: str,
    description: str = "",
    input_schema: Any = None,
    declared_access: str | None = None,
    payload: Any = None,
    policy: str = "block",
    policy_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if stage not in {"descriptor", "call", "result"}:
        raise ValueError("stage must be one of: descriptor, call, result")
    if declared_access is not None and declared_access not in {"read", "write", "admin"}:
        raise ValueError("declared_access must be one of: read, write, admin")

    policy = normalize_policy(policy)
    findings: list[dict[str, Any]] = []

    if stage == "descriptor":
        normalized_payload = "\n".join(
            part
            for part in [
                server_name,
                tool_name,
                description,
                payload_to_text(input_schema),
                declared_access or "",
            ]
            if part
        )
        _append_mcp_descriptor_findings(findings, normalized_payload, "mcp_descriptor", declared_access)
        _append_mcp_policy_findings(
            findings,
            stage="mcp_descriptor",
            server_name=server_name,
            tool_name=tool_name,
            text=normalized_payload,
            payload={"description": description, "input_schema": input_schema},
            policy_config=policy_config,
        )
    elif stage == "call":
        normalized_payload = payload_to_text(payload)
        _append_mcp_call_findings(findings, normalized_payload, "mcp_call")
        _append_mcp_policy_findings(
            findings,
            stage="mcp_call",
            server_name=server_name,
            tool_name=tool_name,
            text=normalized_payload,
            payload=payload,
            policy_config=policy_config,
        )
    else:
        normalized_payload = payload_to_text(payload)
        _append_mcp_result_findings(findings, normalized_payload, "mcp_result")
        _append_mcp_policy_findings(
            findings,
            stage="mcp_result",
            server_name=server_name,
            tool_name=tool_name,
            text=normalized_payload,
            payload=payload,
            policy_config=policy_config,
        )

    findings = dedupe_findings(findings)
    action = resolve_action(findings, policy)
    return {
        "action": action,
        "normalized_payload": normalized_payload,
        "findings": findings,
        "summary": summarize_findings(findings, action),
    }
