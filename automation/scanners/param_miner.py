"""
Hidden parameter discovery — find parameters that exist but aren't documented.
Tests for reflected parameters, hidden inputs, and debug params.
"""

import re
import sys
import os
from urllib.parse import urlparse, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Common hidden/debug parameters
PARAM_WORDLIST = [
    # Debug params
    "debug", "test", "testing", "verbose", "dev", "development",
    "admin", "internal", "trace", "log", "logging", "env",
    # Auth params
    "token", "api_key", "apikey", "key", "secret", "auth",
    "access_token", "session", "jwt", "csrf", "nonce",
    # IDOR params
    "id", "uid", "user_id", "userid", "account", "account_id",
    "profile", "profile_id", "email", "username", "user",
    # File/path params
    "file", "filename", "path", "filepath", "dir", "directory",
    "folder", "doc", "document", "template", "include", "require",
    "page", "pg", "p", "src", "source",
    # Redirect params
    "url", "redirect", "redirect_url", "next", "return", "return_url",
    "goto", "to", "target", "destination", "continue", "callback",
    # Query/search
    "q", "query", "search", "s", "keyword", "find", "filter",
    "sort", "order", "orderby", "limit", "offset", "count",
    # Format/output
    "format", "type", "output", "response_type", "content_type",
    "accept", "encoding", "charset", "lang", "language", "locale",
    # Action params
    "action", "cmd", "command", "exec", "do", "method", "func",
    "function", "handler", "module", "operation", "step",
    # SSRF/injection
    "host", "ip", "domain", "port", "server", "proxy",
    "callback_url", "webhook", "ping", "request",
    # Version/feature flags
    "version", "v", "ver", "feature", "flag", "beta", "experiment",
    "variant", "config", "setting", "option",
    # Misc
    "data", "json", "xml", "body", "payload", "input", "value",
    "name", "title", "description", "comment", "message", "note",
    "category", "tag", "label", "status", "state", "role",
]


def get_baseline(url, client):
    """Get baseline response to compare against."""
    resp = client.get(url)
    if resp:
        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "headers": dict(resp.headers),
            "body": resp.text[:10000],
        }
    return None


def test_param(url, param, value, client, baseline):
    """Test a single parameter. Returns finding info if interesting."""
    parsed = urlparse(url)
    query = urlencode({param: value})
    if parsed.query:
        query = parsed.query + "&" + query
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

    resp = client.get(test_url)
    if not resp:
        return None

    result = {
        "param": param,
        "url": test_url,
        "status": resp.status_code,
        "length": len(resp.content),
        "reflected": value in resp.text,
        "status_changed": resp.status_code != baseline["status"],
        "length_diff": abs(len(resp.content) - baseline["length"]),
    }

    # Interesting if: reflected, status changed, or significant size diff
    is_interesting = (
        result["reflected"]
        or result["status_changed"]
        or result["length_diff"] > 100
    )

    return result if is_interesting else None


def mine(url, verbose=True):
    """Discover hidden parameters on a URL. Returns list of Findings."""
    client = HTTPClient(rate_limit=0.2, timeout=10, retries=1)
    findings = []

    baseline = get_baseline(url, client)
    if not baseline:
        return findings

    canary = "bbhunt7x3k"  # unique string to detect reflection

    if verbose:
        print(f"  Baseline: {baseline['status']} ({baseline['length']} bytes)")
        print(f"  Testing {len(PARAM_WORDLIST)} parameters...", flush=True)

    interesting = []

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(test_param, url, param, canary, client, baseline): param
            for param in PARAM_WORDLIST
        }
        done = 0
        for future in as_completed(futures):
            done += 1
            param = futures[future]
            try:
                result = future.result()
                if result:
                    interesting.append(result)
                    if verbose:
                        flags = []
                        if result["reflected"]:
                            flags.append("REFLECTED")
                        if result["status_changed"]:
                            flags.append(f"STATUS:{result['status']}")
                        if result["length_diff"] > 100:
                            flags.append(f"SIZE_DIFF:{result['length_diff']}")
                        print(f"    [{done}/{len(PARAM_WORDLIST)}] {param}: {' | '.join(flags)}")
            except Exception:
                pass

    # Convert interesting results to findings
    for result in interesting:
        if result["reflected"]:
            findings.append(Finding(
                title=f"Reflected Parameter: {result['param']}",
                severity="medium",
                description=f"Parameter '{result['param']}' reflects its value in the response. Potential XSS vector.",
                url=result["url"],
                evidence=f"Parameter '{result['param']}' with value '{canary}' was reflected in response body.",
                remediation="Ensure all reflected parameters are properly encoded/escaped.",
            ))
        elif result["status_changed"]:
            findings.append(Finding(
                title=f"Hidden Parameter: {result['param']} (status change)",
                severity="low",
                description=f"Parameter '{result['param']}' causes a different HTTP status code ({result['status']} vs {baseline['status']}).",
                url=result["url"],
                evidence=f"Baseline status: {baseline['status']}, With param: {result['status']}",
            ))
        elif result["length_diff"] > 500:
            findings.append(Finding(
                title=f"Hidden Parameter: {result['param']} (content change)",
                severity="info",
                description=f"Parameter '{result['param']}' causes significant response size difference ({result['length_diff']} bytes).",
                url=result["url"],
                evidence=f"Baseline size: {baseline['length']}, With param: {result['length']}",
            ))

    return findings


def scan_multiple(urls, verbose=True):
    """Mine parameters on multiple URLs."""
    all_findings = []
    for url in urls:
        if verbose:
            print(f"\n  [{url}] mining params...", flush=True)
        findings = mine(url, verbose)
        all_findings.extend(findings)
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python param_miner.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] Parameter mining: {url}\n")
    findings = mine(url)
    print(f"\n[+] Interesting parameters: {len(findings)}")
