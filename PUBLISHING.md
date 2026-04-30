# Publishing Checklist

Use this when the repository is ready to go public.

## GitHub

```bash
git init
git add .
git commit -m "Initial public Veil MCP release"
gh repo create Atomics-hub/veil-mcp --public --source=. --remote=origin --push
```

After pushing:

- Enable GitHub security advisories.
- Add repository topics: `mcp`, `ai-security`, `agent-security`, `model-context-protocol`, `firewall`.
- Add branch protection for `main`.
- Add a short demo GIF or terminal recording to the README.

## PyPI

Preferred path: configure PyPI trusted publishing for this GitHub repository.

PyPI project settings:

- Project name: `veil-mcp`
- Owner: `Atomics-hub`
- Repository: `veil-mcp`
- Workflow: `publish.yml`
- Environment: leave blank unless you later add one in GitHub Actions

After trusted publishing is configured, publish from GitHub:

```bash
gh release create v0.1.1 dist/veil_mcp-0.1.1.tar.gz dist/veil_mcp-0.1.1-py3-none-any.whl \
  --title "Veil MCP v0.1.1" \
  --notes "Release notes"
```

Manual token path:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

After publishing:

- Install in a clean environment with `pip install veil-mcp`.
- Run `veil-mcp-proxy --help`.
- Run the smoke demo from a source checkout using the published console script.

## Launch

Suggested launch copy:

> MCP gives AI agents tools. Veil MCP gives those tools a local firewall: block poisoned tool descriptions, secret-file reads, webhook exfiltration, unsafe results, and overbroad servers before they reach your agent.

Good places to post:

- GitHub Trending-adjacent developer circles.
- Hacker News Show HN.
- Reddit communities focused on local AI, agent tooling, and security.
- MCP and AI engineering Discord or Slack communities.
