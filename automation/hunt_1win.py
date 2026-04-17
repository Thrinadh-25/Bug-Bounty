"""
hunt_1win.py — 1win HackerOne program wrapper around automation.hunt

This is a thin, opinionated wrapper around the generic ``automation.hunt``
orchestrator. It hardcodes every program-specific guardrail for the 1win
HackerOne engagement so you can't accidentally burn the program:

    * Rate caps at 4 req/sec and 4 concurrent (program limit is 5/5)
    * stealth mode always, --require-proof always
    * Out-of-scope scanner modules are auto-skipped
    * Per-asset output directories under automation/output/1win/<asset>/
    * Target workspace at targets/active/1win/ is bootstrapped on first run

Usage:
    python -m automation.hunt_1win                                         # recon+scan 1win.com
    python -m automation.hunt_1win --asset 1wrun                           # target 1w.run
    python -m automation.hunt_1win --asset all                             # loop all 3 root domains
    python -m automation.hunt_1win --asset main --only recon               # recon only
    python -m automation.hunt_1win --asset main --cookies "sid=abc"        # authenticated
    python -m automation.hunt_1win --asset main --proxy http://127.0.0.1:8080   # through Burp
    python -m automation.hunt_1win --asset main --resume                   # resume last run
"""

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ---------------------------------------------------------------------------
# Program configuration — these defaults are load-bearing. Do not change them
# without re-reading the 1win HackerOne program policy.
# ---------------------------------------------------------------------------
PROGRAM_NAME   = "1win"
PLATFORM       = "HackerOne"
MODE           = "stealth"    # respects the hard 5 req/sec program cap
MAX_RPS        = 4            # stay under their 5/s limit
MAX_CONCURRENT = 4            # stay under their 5 concurrent limit
REQUIRE_PROOF  = True         # drop unconfirmed high/critical findings

# Modules explicitly out-of-scope per the program rules
SKIP_MODULES = [
    "ssl_scan",
    "headers",
    "dns_zone",
    "crlf",
    "cors",
    "method_tamper",
    "host_header",
]

# In-scope root domains
SCOPE_DOMAINS = [
    "1win.com",
    "1w.run",
    "1w.cash",
]

# Named assets -> target domain. "all" is a sentinel that loops every unique
# root domain sequentially. betting/casino paths live under 1win.com and are
# explored during recon (spider/endpoints) rather than targeted directly.
ASSETS = {
    "main":    "1win.com",
    "betting": "1win.com",
    "casino":  "1win.com",
    "1wrun":   "1w.run",
    "1wcash":  "1w.cash",
    "all":     None,
}

BASE_OUTPUT = os.path.join(HERE, "output", "1win")
WORKSPACE   = os.path.join(
    os.path.dirname(HERE), "targets", "active", "1win"
)


# ---------------------------------------------------------------------------
# Workspace bootstrap
# ---------------------------------------------------------------------------
_WORKSPACE_DIRS = [
    WORKSPACE,
    os.path.join(WORKSPACE, "notes"),
    os.path.join(WORKSPACE, "findings"),
    os.path.join(WORKSPACE, "recon"),
    os.path.join(WORKSPACE, "screenshots"),
]


def bootstrap_workspace():
    """Ensure targets/active/1win/ exists. Silent unless something is created."""
    created = []
    for d in _WORKSPACE_DIRS:
        if not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
            created.append(d)
    gitkeep = os.path.join(WORKSPACE, "screenshots", ".gitkeep")
    if not os.path.exists(gitkeep):
        try:
            open(gitkeep, "w", encoding="utf-8").close()
            created.append(gitkeep)
        except OSError:
            pass
    if created:
        print(f"[workspace] created {len(created)} path(s) under {WORKSPACE}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:80]


def _print_header(assets_list, asset_label):
    bar = "=" * 64
    print(bar)
    print(f"  {PROGRAM_NAME.upper()} — {PLATFORM} program hunt")
    print(bar)
    print(f"  Program       : {PROGRAM_NAME}")
    print(f"  Platform      : {PLATFORM}")
    print(f"  Asset label   : {asset_label}")
    print(f"  Targets       : {', '.join(assets_list)}")
    print(f"  Mode          : {MODE}  (require-proof={REQUIRE_PROOF})")
    print(f"  Rate limits   : {MAX_RPS} req/s, {MAX_CONCURRENT} concurrent "
          f"(program cap: 5/5)")
    print(f"  Skipped       : {', '.join(SKIP_MODULES)}")
    print(f"  Workspace     : {WORKSPACE}")
    print(f"  Output base   : {BASE_OUTPUT}")
    print(bar)


def _apply_rate_cap():
    """Monkey-patch the shared rate profile so the stealth mode used by the
    engine respects the 1win program caps."""
    import automation.core.opsec as _opsec
    # Values the user specified — keep as-is so the config is introspectable.
    _opsec.RATE_PROFILES["stealth"]["rps"] = MAX_RPS
    _opsec.RATE_PROFILES["stealth"]["concurrent"] = MAX_CONCURRENT
    # And the keys the HTTPClient actually reads — rate_limit is the minimum
    # gap between requests in seconds, max_workers is the concurrency cap.
    _opsec.RATE_PROFILES["stealth"]["rate_limit"] = 1.0 / MAX_RPS
    _opsec.RATE_PROFILES["stealth"]["max_workers"] = MAX_CONCURRENT


def _build_namespace(target, asset_key, args):
    """Build the argparse.Namespace that automation.hunt.run expects."""
    ns = argparse.Namespace()
    ns.target        = target
    ns.scope         = None
    ns.output        = os.path.join(BASE_OUTPUT, _safe(asset_key))
    ns.mode          = MODE
    ns.aggressive    = bool(args.aggressive)
    ns.only          = args.only
    ns.skip          = ",".join(SKIP_MODULES)
    ns.cookies       = args.cookies
    ns.headers       = args.headers
    ns.api_keys      = args.api_keys
    ns.proxy         = args.proxy
    ns.tor           = bool(args.tor)
    ns.notify        = args.notify
    ns.resume        = bool(args.resume)
    ns.require_proof = REQUIRE_PROOF
    ns.no_tools      = False
    return ns


def _resolve_targets(asset_key):
    if asset_key == "all":
        # unique root domains, preserving SCOPE_DOMAINS order
        return list(SCOPE_DOMAINS)
    return [ASSETS[asset_key]]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="hunt_1win",
        description=(
            "1win HackerOne program runner — stealth mode, 4 req/s cap, "
            "require-proof, out-of-scope modules pre-skipped."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m automation.hunt_1win\n"
            "  python -m automation.hunt_1win --asset 1wrun\n"
            "  python -m automation.hunt_1win --asset all\n"
            "  python -m automation.hunt_1win --asset main --only recon\n"
            "  python -m automation.hunt_1win --asset main --cookies 'sid=abc'\n"
            "  python -m automation.hunt_1win --asset main --proxy http://127.0.0.1:8080\n"
            "  python -m automation.hunt_1win --asset main --resume\n"
        ),
    )
    parser.add_argument("--asset", default="main", choices=list(ASSETS.keys()),
                        help="Which in-scope asset to hunt (default: main)")
    parser.add_argument("--cookies", help='Raw Cookie header, e.g. "sid=abc; csrf=xyz"')
    parser.add_argument("--headers", help="Path to a headers file (Name: value per line)")
    parser.add_argument("--api-keys", dest="api_keys",
                        help="Path to api_keys.json (shodan/censys/github)")
    parser.add_argument("--proxy", help="Upstream proxy URL (e.g. http://127.0.0.1:8080 for Burp)")
    parser.add_argument("--tor", action="store_true", help="Route via local TOR SOCKS proxy")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from the previous trigger_state.json")
    parser.add_argument("--only", choices=["recon", "scan", "exploit"],
                        help="Only run a single phase")
    parser.add_argument("--aggressive", action="store_true",
                        help="Forward aggressive flag (WARNING: 1win is hard rate-limited)")
    parser.add_argument("--notify", help="Slack webhook URL for completion notification")
    args = parser.parse_args()

    bootstrap_workspace()

    if args.aggressive:
        print("[warn] --aggressive requested: 1win has a HARD 5 req/sec cap. "
              "Rate profile patch will still enforce 4 rps / 4 concurrent.")

    targets = _resolve_targets(args.asset)
    _print_header(targets, args.asset)

    # Apply the rate cap exactly once, before any hunt runs.
    _apply_rate_cap()

    # Import after the patch so any module that pre-reads RATE_PROFILES still
    # sees the override (most access it lazily via attribute lookup).
    from automation.hunt import run as hunt_run

    exit_code = 0
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n[{i}/{len(targets)}] === {target} ===")
        # For --asset all, key each target's output dir by the root domain
        # rather than the sentinel "all".
        asset_key = args.asset if args.asset != "all" else target
        ns = _build_namespace(target, asset_key, args)
        try:
            hunt_run(ns)
        except KeyboardInterrupt:
            print(f"\n[abort] interrupted during {target}")
            exit_code = 130
            break
        except Exception as exc:
            print(f"[error] hunt failed for {target}: {exc}")
            exit_code = 1
            # Keep going with the next asset in --asset all mode
            continue

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
