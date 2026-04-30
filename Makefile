.PHONY: test smoke help

test:
	python -m unittest discover -s tests

smoke:
	python scripts/smoke_mcp_proxy.py

help:
	veil-mcp-proxy --help
