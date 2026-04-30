# Contributing

Thanks for helping make MCP agent workflows safer.

## Local Setup

```bash
python -m pip install -e .
python -m unittest discover -s tests
python scripts/smoke_mcp_proxy.py
```

## Pull Requests

Good changes usually include:

- A focused description of the MCP risk or workflow being improved.
- Unit tests for policy behavior.
- A smoke-test update when proxy behavior changes.
- Documentation updates for new policy fields or CLI flags.

Keep default behavior conservative. Veil should prefer explicit allowlists, redacted audit logs, and local-only operation.
