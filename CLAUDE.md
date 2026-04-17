# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A personal bug-bounty workspace. Two distinct layers:

- `automation/` — a Python framework (`hunt.py`) that orchestrates recon → scan → targeted-exploit → report against a target. All code changes happen here.
- `cheatsheets/`, `checklists/`, `notes/`, `recon/`, `reports/`, `resources/`, `scripts/`, `targets/`, `tracking/` — hunter-facing markdown notes and per-target workspaces. Not code. Only touch when the user asks.

## Common commands

```bash
# All commands are run from the repo root. Windows + bash — use forward slashes.
python -m automation.setup_verify              # sanity-check: imports, dirs, tool availability
python -m automation.setup_verify --fix        # create any missing directories
python -m automation.setup_verify --json       # machine-readable output

python -m automation.hunt --target example.com                          # standard run
python -m automation.hunt --target example.com --mode deep --aggressive # full arsenal
python -m automation.hunt --target example.com --mode stealth --tor     # low-and-slow via TOR
python -m automation.hunt --target example.com --only recon             # phase isolation
python -m automation.hunt --target example.com --skip sqli,xss,ports    # per-module skip
python -m automation.hunt --target example.com --resume                 # resume from trigger_state.json
python -m automation.hunt --target example.com --require-proof          # drop unconfirmed high/critical

pip install -r automation/requirements.txt     # minimal Python deps (requests, aiohttp, bs4, dnspython, colorama)
```

There is no test suite, no linter config, and no CI. `setup_verify` is the closest thing to a build check: it imports every module in `automation/*` and reports failures — run it after any structural edit.

## Architecture — the big picture

The framework is **trigger-driven**. Recon and scanners don't call exploits directly; they emit *signals* (open port, detected tech, confirmed finding, leaked secret, cloud-asset candidate), and `core/trigger_engine.py` maps signals → exploit modules via `TRIGGER_MAP` and dispatches them through a `ThreadPoolExecutor`. Every (module, target) pair fires at most once, tracked in `output/<target>/trigger_state.json` so `--resume` works.

Pipeline in `automation/hunt.py`:

1. **setup** — load scope, API keys, sessions, OpSec mode, interactsh listener.
2. **recon** (`automation/recon/`) — subdomains, live-check, nmap, tech fingerprint, JS secrets, dir brute, crawl, ASN, cloud-asset candidates, GitHub/Shodan/Censys dorks, Wayback secret sweep.
3. **scan** (`automation/scanners/`) — surface scanners: headers, CORS, SSL, host-header, CRLF, open-redirect, method-tamper, GraphQL, takeover, params, SQLi, XSS, SSRF, rate-limit, DNS.
4. **trigger** (`automation/exploits/` via `core/trigger_engine.py`) — confirmation + deeper-impact modules keyed off recon/scan output.
5. **verify** — `core/verifier.py` runs proof-of-impact regex checks; `--require-proof` drops unconfirmed high/critical findings.
6. **report** — `utils/reporter.py` emits markdown, executive markdown, HackerOne JSON, Bugcrowd JSON, and styled HTML.

### Module contracts — respect these exactly

- **Exploit modules** (`automation/exploits/*.py`) — every file exposes `run(context, client=None, aggressive=False, timeout=60) -> list[Finding]`. `context` is a dict like `{"url": ..., "host": ..., "port": ..., "tech": ..., "secret": ..., "finding": Finding}` populated by the trigger engine. Modules must never raise; on error, return `[]`. Use `_common.py` helpers (`have(tool)`, `run_cmd(...)`, `ctx_url`, `ctx_host`, `make_client`) — they return structured failure values instead of exceptions.
- **Recon modules** (`automation/recon/*.py`) — two older calling conventions exist (`enumerate(target)`, `check_hosts(hosts)`, `fingerprint_multiple(urls)`, `scan(host, type)`, etc.) plus the newer `run(target, api_keys=None, client=None, timeout=...)` pattern added for ASN / cloud / GitHub / Shodan / Censys / Wayback. Don't normalize these without also updating every caller in `hunt.py`.
- **Scanner modules** (`automation/scanners/*.py`) — `scan_multiple(urls)` is the main entry; `detect_waf(url)` and `scan(target)` are one-offs. Return `list[Finding]`.
- **`Finding`** (`utils/reporter.py`) — has `__slots__`. Backward compatible with positional `Finding(title, severity, description, url, evidence, remediation)`. New code should set `finding_type` (lowercase tag — `sqli`, `xss`, `ssrf`, `rce`, `credential_exposure`, etc.) because the trigger engine uses it to route signals, and the reporter uses it to pick CVSS base scores.

### Tool-availability philosophy

External tools (sqlmap, ghauri, ffuf, nuclei, dalfox, interactsh-client, dig, whois, jwt_tool, …) are wrapped when present but **every wrapper has a Python fallback** — this framework runs on Windows with almost nothing installed. When editing exploit modules: always gate external-tool branches on `have("tool")` and supply a fallback. `--no-tools` sets `BB_NO_TOOLS=1` to force fallbacks even when tools exist.

### Core components (`automation/core/`)

- `trigger_engine.py` — `TRIGGER_MAP` is the single source of truth for signal → module routing. Adding a new exploit module requires both the file *and* a TRIGGER_MAP entry.
- `verifier.py` — `PROOF_PATTERNS` regex dict per `finding_type`; `reject_unproven(findings, require_proof_for=...)` is the pruning gate.
- `session_manager.py` — multi-session auth; `Session.refresh()` on 401. `--cookies` / `--headers` feed into the default session.
- `opsec.py` — rate profile `stealth|standard|deep|aggressive`, proxy + TOR (`socks5h://127.0.0.1:9050`), per-tool signature customization via `OpSec.tool_args(name)`.
- `interactsh.py` — `InteractshCLI` wraps `interactsh-client`; `OfflineStub` no-ops when the binary is absent. `get_listener(prefer_cli=True)` is the entry point; callers must check `listener.enabled`.

### HTTP client (`utils/http.py`)

Every HTTP request goes through `HTTPClient` — never `requests.get` directly. It layers: rate profiles (`RATE_PROFILES`), UA rotation, exponential backoff with jitter (`min(30, 2**attempt * 0.5) + uniform(0, 0.5)`), proxy/TOR, cookies/headers injection, and concurrency caps.

## Output layout

Per-target results go to `automation/output/<target>/`:
- `recon/*.json|.txt` — raw recon artifacts
- `findings/<scanner>.json` — per-scanner findings
- `trigger_state.json` — resume state (fired modules + events)
- `verification_log.json` — emitted when `--require-proof` is used
- `report.md`, `report_executive.md`, `report_hackerone.json`, `report_bugcrowd.json`, `report.html`

## Environment notes

- Windows 11 + bash. Use forward slashes and `/dev/null`, not `NUL`.
- The git repo flag is off (`Is a git repository: false`) — don't assume git context.
