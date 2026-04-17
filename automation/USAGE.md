# Bug Bounty Automation — Usage

Run everything **from the repo root**, not from inside `automation/`. All commands use `python -m automation.<module>` so Python's package system resolves imports correctly.

```
C:\Users\Thrinadh reddy\Desktop\Bug Bounty   <- cd here
```

---

## 1. First-time setup

```bash
pip install -r automation/requirements.txt
python -m automation.setup_verify --fix
```

`setup_verify` walks every module in `automation/`, imports it, and prints:

- which directories are missing (`--fix` creates them)
- which Python modules fail to import (should always be zero)
- which external tools are on `PATH` vs. which will fall back to pure-Python

Missing external tools are **not** an error — every wrapper has a Python fallback. The framework runs on Windows with zero Kali tools installed.

```bash
python -m automation.setup_verify --json     # machine-readable
```

---

## 2. Running a hunt

Minimum:

```bash
python -m automation.hunt --target example.com
```

Full arsenal:

```bash
python -m automation.hunt \
  --target example.com \
  --scope automation/scopes/example.txt \
  --mode deep --aggressive \
  --api-keys automation/api_keys.json \
  --cookies "session=abc; csrf=xyz" \
  --headers automation/headers.txt \
  --notify https://hooks.slack.com/services/XXX/YYY/ZZZ \
  --require-proof
```

### Modes

| Mode | Concurrency | Delay + Jitter | Crawl pages | Port scan | Aggressive default |
|------|-------------|----------------|-------------|-----------|--------------------|
| `quick` | 10 | 0.5 s + 0.3 s | 10 | off | no |
| `standard` (default) | 10 | 0.5 s + 0.3 s | 30 | off | no |
| `deep` | 30 | 0 s | 100 | on | **yes** |
| `stealth` | 1 | 2 s + 1 s | 20 | off | no |

`--aggressive` overrides the mode default and unlocks intrusive probes inside exploit modules (e.g. S3 write test, SSH brute).

### Phase isolation

```bash
--only recon          # recon phase only
--only scan           # scanners only (auto-runs trigger engine)
--only exploit        # just the trigger engine over whatever findings/recon are already saved
--skip sqli,xss,ports # skip individual modules by short name
```

Short names that `--skip` understands:
`subdomains, live, ports, tech, dirs, crawl, js, endpoints, asn, cloud, github, shodan, censys, wayback, dns, headers, cors, ssl, host_header, crlf, open_redirect, methods, graphql, takeover, params, sqli, xss, ssrf, rate_limit`

### Resume

```bash
python -m automation.hunt --target example.com --resume
```

Reads `automation/output/<target>/trigger_state.json` and skips any `(module, target)` pair already fired.

### Proxy / TOR

```bash
--proxy http://127.0.0.1:8080    # route through Burp
--tor                            # route through local TOR SOCKS (socks5h://127.0.0.1:9050)
```

### Force Python fallbacks

```bash
--no-tools    # never shell out to sqlmap/nuclei/etc. even if present
```

---

## 3. Where to put things

All input files live under `automation/`. Create these folders yourself the first time — they're not version-controlled.

### 3a. Scope file → `automation/scopes/<target>.txt`

Template lives at `automation/scope_template.txt`. Copy and edit:

```
[in-scope]
*.example.com
api.example.com
example.com

[out-of-scope]
admin.example.com
*.internal.example.com

[rules]
no-dos
rate-limit-10-requests-per-second
```

Pass with `--scope automation/scopes/example.txt`. Wildcards (`*.foo.com`) are supported.

### 3b. API keys → `automation/api_keys.json`

Picked up automatically if the path is passed via `--api-keys`. Otherwise the framework reads `SHODAN_*`, `CENSYS_*`, `GITHUB_*`, `IPINFO_*` from the environment.

```json
{
  "github": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "shodan": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "censys_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "censys_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "ipinfo": "xxxxxxxxxxxxxx"
}
```

Keys are only used for the recon modules that need them (`github_recon`, `shodan_recon`, `censys_recon`, `asn_enum`). Missing keys → those modules silently skip.

### 3c. Authenticated sessions

Two ways, either or both:

**Cookies** — raw `Cookie:` header value:

```bash
--cookies "session=abc123; csrf=xyz789; user_id=42"
```

**Headers file** → `automation/headers.txt`:

```
Authorization: Bearer eyJhbGciOi...
X-CSRF-Token: 7f83b1657ff1fc53
X-Custom-Auth: internal-app-v2
# lines starting with # are ignored
```

Pass with `--headers automation/headers.txt`. Both cookies and headers attach to every outgoing request in the hunt.

### 3d. Target list (for batch hunting)

Not wired into `hunt.py` directly — loop in shell:

```bash
while IFS= read -r t; do
  python -m automation.hunt --target "$t" --mode standard
done < automation/targets.txt
```

---

## 4. Output

Everything lands in `automation/output/<sanitized_target>/`:

```
output/example_com/
├── recon/
│   ├── subdomains.txt
│   ├── live_hosts.txt
│   ├── technologies.json
│   ├── asn.json
│   ├── cloud_candidates.json
│   ├── github.json  shodan.json  censys.json  wayback.json
│   └── js_findings.json
├── findings/
│   ├── sqli.json   xss.json   ssrf.json   ...
├── trigger_state.json            <- resume state
├── verification_log.json         <- only with --require-proof
├── report.md                     <- full markdown
├── report_executive.md           <- exec summary
├── report_hackerone.json         <- paste into H1 submission
├── report_bugcrowd.json          <- paste into Bugcrowd submission
└── report.html                   <- styled HTML, open in browser
```

---

## 5. Typical workflows

### Brand-new target, time-boxed recon

```bash
python -m automation.hunt --target target.com --only recon --mode quick
```

Review `output/target_com/recon/` then decide where to dig deeper.

### Authenticated deep scan on one endpoint

```bash
python -m automation.hunt \
  --target app.target.com \
  --mode deep --aggressive \
  --cookies "sid=..." \
  --scope automation/scopes/target.txt \
  --require-proof
```

### Stealth mode behind Burp

```bash
python -m automation.hunt --target target.com --mode stealth --proxy http://127.0.0.1:8080
```

### Resume an interrupted hunt

```bash
python -m automation.hunt --target target.com --resume
```

### Re-run only the exploit phase against saved findings

```bash
python -m automation.hunt --target target.com --only exploit
```

---

## 6. Slack notification

Any incoming webhook URL works:

```bash
--notify https://hooks.slack.com/services/T00/B00/XXX
```

A summary line per severity is posted at hunt completion.

---

## 7. Troubleshooting

- **Imports failing** → `python -m automation.setup_verify` pinpoints the module.
- **Every finding says "(unconfirmed)"** → drop `--require-proof` or check `verification_log.json` for the regex that didn't match.
- **Hangs on a single module** → each module has an internal timeout (default 60 s). If a whole phase hangs, the `trigger_state.json` `events` list shows which module last ran.
- **No HTTP traffic leaves the machine** → check `--proxy` / `--tor` values; `HTTPS_PROXY` env also respected.
- **Windows path issues** → always use forward slashes in arguments (`automation/scopes/x.txt`).
