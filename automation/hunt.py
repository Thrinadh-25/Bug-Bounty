"""
hunt.py — Master Bug Bounty Automation Orchestrator v3

Pipeline:
    1. setup   — load scope, api_keys, sessions, opsec, interactsh
    2. recon   — subdomains, live, ports, tech, JS, dirs, crawl, ASN, cloud, github, shodan, censys, wayback
    3. scan    — every surface-level scanner (fed by recon output)
    4. trigger — feed port/tech/finding/secret/infra signals into the TriggerEngine,
                 firing targeted exploit modules for confirmation + deeper impact
    5. verify  — Verifier prunes un-proofed high/critical findings if --require-proof
    6. report  — md / exec md / H1 json / bugcrowd json / html

Usage:
    python -m automation.hunt --target example.com
    python -m automation.hunt --target example.com --mode deep --aggressive
    python -m automation.hunt --target example.com --only recon
    python -m automation.hunt --target example.com --skip sqli,xss
    python -m automation.hunt --target example.com --api-keys keys.json \\
        --cookies "session=abc; user=42" --headers headers.txt
    python -m automation.hunt --target example.com --mode stealth --tor
    python -m automation.hunt --target example.com --resume
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from utils.scope import ScopeChecker
from utils.reporter import Reporter, Finding

from core.trigger_engine import TriggerEngine
from core.verifier import Verifier, reject_unproven
from core.session_manager import SessionManager
from core.opsec import OpSec
from core.interactsh import get_listener


BANNER = r"""
 ____              _   _             _
| __ ) _   _  __ _| | | |_   _ _ __ | |_
|  _ \| | | |/ _` | |_| | | | | '_ \| __|
| |_) | |_| | (_| |  _  | |_| | | | | |_
|____/ \__,_|\__, |_| |_|\__,_|_| |_|\__|
             |___/       v3 — Trigger Engine
"""


MODES = {
    "quick":    {"scan_limit": 5,  "deep": False, "crawl_pages": 10, "aggressive_default": False},
    "standard": {"scan_limit": 15, "deep": False, "crawl_pages": 30, "aggressive_default": False},
    "deep":     {"scan_limit": 40, "deep": True,  "crawl_pages": 100, "aggressive_default": True},
    "stealth":  {"scan_limit": 8,  "deep": False, "crawl_pages": 20, "aggressive_default": False},
}


def banner(msg):
    bar = "=" * 60
    print(f"\n{bar}\n  {msg}\n{bar}")


def load_api_keys(path):
    if not path or not os.path.isfile(path):
        env = {k: v for k, v in os.environ.items() if k.startswith(("SHODAN_", "CENSYS_", "GITHUB_", "IPINFO_"))}
        return env
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def notify_slack(webhook, text):
    try:
        import urllib.request
        req = urllib.request.Request(webhook, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        pass


def _safe_name(s):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:80]


def _import_if(name):
    try:
        return __import__(name, fromlist=["*"])
    except Exception as e:
        print(f"  [warn] {name} not importable: {e}")
        return None


def _skip(name, skip_set):
    return name in skip_set


def run_recon(target, reporter, scope, client, mode_cfg, skip, api_keys, log):
    subdomains = [target]
    live_results = []
    live_hosts = [target]
    live_urls = [f"https://{target}"]
    urls_with_params = []
    tech_results = {}
    port_results = {}
    js_findings = {"secrets": [], "endpoints": [], "emails": [], "js_files": []}
    cloud_candidates = {"s3": [], "gcs": [], "azure": []}

    # --- subdomain enum ---
    if not _skip("subdomains", skip):
        banner("SUBDOMAIN ENUMERATION")
        mod = _import_if("recon.subdomains")
        if mod and hasattr(mod, "enumerate"):
            subdomains = mod.enumerate(target) or [target]
            subdomains = scope.filter_targets(subdomains) or [target]
            reporter.save_recon("subdomains.txt", subdomains)
            log(f"  [+] {len(subdomains)} in-scope subdomains")

    # --- live host check ---
    if not _skip("live", skip):
        banner("LIVE HOST DISCOVERY")
        mod = _import_if("recon.live_check")
        if mod and hasattr(mod, "check_hosts"):
            live_results = mod.check_hosts(subdomains) or []
            live_hosts = [r["host"] for r in live_results] or [target]
            live_urls = [r["url"] for r in live_results] or [f"https://{target}"]
            reporter.save_recon("live_hosts.txt", live_urls)
            reporter.save_recon("live_hosts_full.json", live_results)
            log(f"  [+] {len(live_hosts)} live hosts")

    # --- port scan ---
    if not _skip("ports", skip) and mode_cfg["deep"]:
        banner("PORT SCANNING")
        mod = _import_if("recon.nmap_scan")
        if mod and hasattr(mod, "scan"):
            for h in live_hosts[:10]:
                port_results[h] = mod.scan(h, "default")
            reporter.save_recon("ports.json", port_results)

    # --- tech fingerprint ---
    if not _skip("tech", skip):
        banner("TECHNOLOGY FINGERPRINTING")
        mod = _import_if("recon.tech_detect")
        if mod and hasattr(mod, "fingerprint_multiple"):
            tech_results = mod.fingerprint_multiple(live_urls[:mode_cfg["scan_limit"]]) or {}
            reporter.save_recon("technologies.json", tech_results)

    # --- dir brute + sensitive files ---
    if not _skip("dirs", skip) and mode_cfg["deep"]:
        banner("DIRECTORY BRUTE + SENSITIVE FILES")
        mod = _import_if("recon.dir_brute")
        if mod:
            for url in live_urls[:5]:
                if hasattr(mod, "brute"):
                    reporter.save_recon(f"dirs_{_safe_name(url)}.json", mod.brute(url))
                if hasattr(mod, "sensitive_file_check"):
                    reporter.add_findings(mod.sensitive_file_check(url))

    # --- web crawl ---
    if not _skip("crawl", skip):
        banner("WEB CRAWLING")
        mod = _import_if("recon.spider")
        if mod and hasattr(mod, "crawl"):
            for url in live_urls[:3]:
                crawl = mod.crawl(url, scope=scope, max_pages=mode_cfg["crawl_pages"]) or {}
                reporter.save_recon(f"crawl_{_safe_name(url)}.json", crawl)
                for u in crawl.get("urls", []):
                    if "?" in u and scope.is_in_scope(u):
                        urls_with_params.append(u)

    # --- JS recon ---
    if not _skip("js", skip):
        banner("JAVASCRIPT ANALYSIS")
        mod = _import_if("recon.js_recon")
        if mod and hasattr(mod, "recon"):
            for url in live_urls[:mode_cfg["scan_limit"]]:
                r = mod.recon(url) or {}
                for k in js_findings:
                    js_findings[k] = list(js_findings[k]) + list(r.get(k, []))
            for k in ("endpoints", "emails", "js_files"):
                js_findings[k] = sorted(set(js_findings[k]))
            reporter.save_recon("js_findings.json", js_findings)
            for sec in js_findings["secrets"]:
                reporter.add_finding(Finding(
                    title=f"Exposed secret in JS: {sec.get('type','?')}",
                    severity="high",
                    finding_type="credential_exposure",
                    description="Secret discovered in client-side JavaScript.",
                    url=sec.get("source", ""),
                    evidence=str(sec.get("value", ""))[:200],
                    remediation="Remove secrets from client-side code; rotate the leaked value.",
                ))

    # --- passive endpoints ---
    if not _skip("endpoints", skip):
        banner("ENDPOINT DISCOVERY (PASSIVE)")
        mod = _import_if("recon.endpoints")
        if mod and hasattr(mod, "discover"):
            ep = mod.discover(target) or {}
            reporter.save_recon("endpoints.txt", ep.get("urls", []))
            for u in (ep.get("categories", {}).get("with_params", []) or []):
                if scope.is_in_scope(u):
                    urls_with_params.append(u)
    urls_with_params = sorted(set(urls_with_params))

    # --- ASN ---
    if not _skip("asn", skip):
        banner("ASN / NETBLOCK ENUMERATION")
        mod = _import_if("recon.asn_enum")
        if mod and hasattr(mod, "run"):
            reporter.save_recon("asn.json", mod.run(target, api_keys=api_keys, client=client))

    # --- cloud candidates ---
    if not _skip("cloud", skip):
        banner("CLOUD ASSET ENUMERATION")
        mod = _import_if("recon.cloud_assets")
        if mod and hasattr(mod, "run"):
            cloud_candidates = mod.run(target, api_keys=api_keys, client=client) or cloud_candidates
            reporter.save_recon("cloud_candidates.json", cloud_candidates)

    # --- github ---
    if not _skip("github", skip) and (api_keys.get("github") or api_keys.get("GITHUB_TOKEN")):
        banner("GITHUB DORKING")
        mod = _import_if("recon.github_recon")
        if mod and hasattr(mod, "run"):
            reporter.save_recon("github.json", mod.run(target, api_keys=api_keys, client=client))

    # --- shodan ---
    if not _skip("shodan", skip) and (api_keys.get("shodan") or api_keys.get("SHODAN_API_KEY")):
        banner("SHODAN LOOKUP")
        mod = _import_if("recon.shodan_recon")
        if mod and hasattr(mod, "run"):
            s = mod.run(target, api_keys=api_keys, client=client) or {}
            reporter.save_recon("shodan.json", s)
            for svc in s.get("services", []):
                p = svc.get("port")
                if p:
                    port_results.setdefault(s.get("host"), {"ports": []})["ports"].append(
                        {"port": p, "service": svc.get("product") or "", "version": svc.get("version") or ""}
                    )

    # --- censys ---
    if not _skip("censys", skip) and (api_keys.get("censys_id") or api_keys.get("CENSYS_API_ID")):
        banner("CENSYS LOOKUP")
        mod = _import_if("recon.censys_recon")
        if mod and hasattr(mod, "run"):
            reporter.save_recon("censys.json", mod.run(target, api_keys=api_keys, client=client))

    # --- wayback secret sweep ---
    if not _skip("wayback", skip):
        banner("WAYBACK MACHINE SECRET SWEEP")
        mod = _import_if("recon.wayback_secrets")
        if mod and hasattr(mod, "run"):
            wb = mod.run(target, api_keys=api_keys, client=client) or {}
            reporter.save_recon("wayback.json", wb)
            for s in wb.get("secrets", []):
                reporter.add_finding(Finding(
                    title=f"Archived secret: {s['type']}",
                    severity="high",
                    finding_type="credential_exposure",
                    description="Secret recovered from archived content on the Wayback Machine.",
                    url=s.get("url", ""),
                    evidence=str(s.get("match", ""))[:160],
                    remediation="Rotate the leaked credential; the archive cannot be recalled.",
                ))

    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "live_urls": live_urls,
        "urls_with_params": urls_with_params,
        "tech_results": tech_results,
        "port_results": port_results,
        "js_findings": js_findings,
        "cloud_candidates": cloud_candidates,
    }


def run_scan(reporter, scope, recon, mode_cfg, skip, log):
    live_urls = recon["live_urls"]
    live_hosts = recon["live_hosts"]
    subdomains = recon["subdomains"]
    urls_with_params = recon["urls_with_params"]
    scan_urls = live_urls or [f"https://{subdomains[0]}"]
    lim = mode_cfg["scan_limit"]

    scanners = [
        ("dns",           "scanners.dns_zone",      "scan",           [subdomains[0]]),
        ("headers",       "scanners.headers",       "scan_multiple",  [scan_urls[:lim]]),
        ("cors",          "scanners.cors",          "scan_multiple",  [scan_urls[:lim]]),
        ("ssl",           "scanners.ssl_scan",      "scan_multiple",  [list(set(live_hosts))[:lim]]),
        ("host_header",   "scanners.host_header",   "scan_multiple",  [scan_urls[:lim]]),
        ("crlf",          "scanners.crlf",          "scan_multiple",  [scan_urls[:lim]]),
        ("open_redirect", "scanners.open_redirect", "scan_multiple",  [scan_urls[:10]]),
        ("methods",       "scanners.method_tamper", "scan_multiple",  [scan_urls[:lim]]),
        ("graphql",       "scanners.graphql",       "scan_multiple",  [scan_urls[:lim]]),
        ("takeover",      "scanners.takeover",      "scan",           [subdomains]),
        ("params",        "scanners.param_miner",   "scan_multiple",  [scan_urls[:5]]),
    ]
    if urls_with_params:
        scanners += [
            ("sqli", "scanners.sqli", "scan_multiple", [urls_with_params[:lim]]),
            ("xss",  "scanners.xss",  "scan_multiple", [urls_with_params[:lim]]),
        ]
    scanners += [
        ("ssrf",       "scanners.ssrf",       "scan_multiple", [scan_urls[:10]]),
        ("rate_limit", "scanners.rate_limit", "scan_multiple", [scan_urls[:3]]),
    ]

    for name, mod_name, fn_name, args in scanners:
        if _skip(name, skip):
            continue
        if name == "rate_limit" and not mode_cfg["deep"]:
            continue
        banner(f"SCAN: {name.upper()}")
        mod = _import_if(mod_name)
        if not mod or not hasattr(mod, fn_name):
            log(f"  [skip] {mod_name}.{fn_name} not available")
            continue
        try:
            findings = getattr(mod, fn_name)(*args) or []
        except Exception as e:
            log(f"  [error] {mod_name}.{fn_name}: {e}")
            findings = []
        reporter.add_findings(findings)
        reporter.save_findings(name, findings)
        log(f"  [+] {name}: {len(findings)}")


def run_triggers(engine, reporter, recon, log):
    banner("TRIGGER ENGINE — exploit confirmation")
    signals = []
    signals += engine.from_nmap(recon["port_results"])
    signals += engine.from_tech(recon["tech_results"])
    signals += engine.from_findings(list(reporter.findings))

    secrets = []
    for s in recon["js_findings"].get("secrets", []):
        secrets.append({"type": s.get("type", "").lower(), "value": s.get("value"), "source": s.get("source", "")})
    signals += engine.from_secrets(secrets)

    infra = []
    for b in recon["cloud_candidates"].get("s3", [])[:30]:
        infra.append({"kind": "s3_bucket", "name": b, "buckets": recon["cloud_candidates"]["s3"]})
    for b in recon["cloud_candidates"].get("gcs", [])[:30]:
        infra.append({"kind": "gcs_bucket", "name": b, "buckets": recon["cloud_candidates"]["gcs"]})
    for b in recon["cloud_candidates"].get("azure", [])[:20]:
        infra.append({"kind": "azure_blob", "name": b, "accounts": recon["cloud_candidates"]["azure"]})
    signals += engine.from_infra(infra)

    log(f"  [+] {len(signals)} signals queued")
    new_findings = engine.fire(signals)
    log(f"  [+] {len(new_findings)} new findings from triggers")


def run(args):
    print(BANNER)
    target = args.target
    mode_cfg = MODES[args.mode]
    aggressive = args.aggressive or mode_cfg["aggressive_default"]
    skip = set(s.strip() for s in (args.skip or "").split(",") if s.strip())
    only = args.only
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  Target     : {target}")
    print(f"  Mode       : {args.mode}{' + aggressive' if aggressive else ''}")
    print(f"  Start      : {started}")

    # scope
    scope = ScopeChecker()
    scope.add_target(target)
    if args.scope and os.path.isfile(args.scope):
        scope.load_from_file(args.scope)
        print(f"  Scope file : {args.scope}")

    # output
    out_dir = args.output or os.path.join(HERE, "output", _safe_name(target))
    reporter = Reporter(target, out_dir)
    state_path = os.path.join(out_dir, "trigger_state.json")
    print(f"  Output     : {out_dir}")

    # api keys
    api_keys = load_api_keys(args.api_keys)
    print(f"  API keys   : {list(api_keys.keys()) or '(none)'}")

    # opsec
    opsec = OpSec(mode=args.mode, proxy=args.proxy, use_tor=args.tor)
    client = opsec.new_client()

    # sessions
    sm = SessionManager()
    if args.cookies or args.headers:
        sm.add("default",
               cookies=args.cookies,
               headers_file=args.headers if args.headers and os.path.isfile(args.headers) else None)
        sess = sm.get("default")
        if sess and sess.cookies:
            client.session.cookies.update(sess.cookies)
        if sess and sess.headers:
            client.session.headers.update(sess.headers)

    # interactsh listener (primary for OOB confirmations)
    listener = get_listener(prefer_cli=True)
    if listener.enabled:
        print(f"  OOB host   : {listener.host}")
    else:
        print("  OOB host   : (offline stub)")

    # verifier
    verifier = Verifier()

    # trigger engine
    engine = TriggerEngine(
        reporter=reporter, scope=scope, client=client, opsec=opsec,
        session_manager=sm, interactsh=listener, verifier=verifier,
        aggressive=aggressive, state_path=state_path, logger=print,
    )
    if args.resume and os.path.isfile(state_path):
        engine.load_state()
        print(f"  Resumed from {state_path}")

    # --- pipeline ---
    recon_data = None
    if only in (None, "recon"):
        recon_data = run_recon(target, reporter, scope, client, mode_cfg, skip, api_keys, print)
    else:
        recon_data = {
            "subdomains": [target], "live_hosts": [target],
            "live_urls": [f"https://{target}"], "urls_with_params": [],
            "tech_results": {}, "port_results": {}, "js_findings": {"secrets": []},
            "cloud_candidates": {"s3": [], "gcs": [], "azure": []},
        }

    if only in (None, "scan"):
        run_scan(reporter, scope, recon_data, mode_cfg, skip, print)

    if only in (None, "exploit", "scan"):
        run_triggers(engine, reporter, recon_data, print)

    # verifier pruning (optional)
    if args.require_proof:
        before = len(reporter.findings)
        reporter.findings = reject_unproven(list(reporter.findings))
        print(f"  [verifier] pruned {before - len(reporter.findings)} unproven findings")
        verifier.save_log(os.path.join(out_dir, "verification_log.json"))

    # --- report ---
    banner("GENERATING REPORT")
    paths = reporter.generate_report()
    for p in (paths if isinstance(paths, (list, tuple)) else [paths]):
        print(f"  report: {p}")

    # summary
    sev_counts = {}
    for f in reporter.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary_lines = [f"HUNT COMPLETE: {target} (mode={args.mode})",
                     f"Total findings: {len(reporter.findings)}"]
    for s in ("critical", "high", "medium", "low", "info"):
        if s in sev_counts:
            summary_lines.append(f"  {s.upper():8s} {sev_counts[s]}")
    for ln in summary_lines:
        print("  " + ln)

    if args.notify:
        notify_slack(args.notify, "\n".join(summary_lines))

    return reporter


def main():
    p = argparse.ArgumentParser(prog="hunt", description="Bug Bounty Automation v3 — Trigger Engine")
    p.add_argument("--target", "-t", required=True, help="Target domain or URL")
    p.add_argument("--scope", "-s", help="Scope file (one domain / CIDR per line)")
    p.add_argument("--output", "-o", help="Output directory")
    p.add_argument("--mode", choices=list(MODES.keys()), default="standard",
                   help="quick | standard | deep | stealth")
    p.add_argument("--aggressive", action="store_true", help="Enable aggressive / intrusive probes")
    p.add_argument("--only", choices=["recon", "scan", "exploit"],
                   help="Only run one phase (exploit = trigger engine only)")
    p.add_argument("--skip", help="Comma-separated module names to skip (e.g. sqli,xss,ports)")
    p.add_argument("--cookies", help='Raw Cookie header value, e.g. "sid=abc; csrf=xyz"')
    p.add_argument("--headers", help="Path to headers file (Name: value per line)")
    p.add_argument("--api-keys", dest="api_keys", help="Path to api_keys.json")
    p.add_argument("--proxy", help="Upstream proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--tor", action="store_true", help="Route via local TOR SOCKS proxy")
    p.add_argument("--notify", help="Slack webhook URL for completion notification")
    p.add_argument("--resume", action="store_true", help="Resume from previous trigger_state.json")
    p.add_argument("--require-proof", action="store_true",
                   help="Drop high/critical findings lacking confirmed proof")
    p.add_argument("--no-tools", action="store_true",
                   help="Force Python fallbacks only (do not spawn external tools)")
    args = p.parse_args()

    if args.no_tools:
        os.environ["BB_NO_TOOLS"] = "1"

    run(args)


if __name__ == "__main__":
    main()
