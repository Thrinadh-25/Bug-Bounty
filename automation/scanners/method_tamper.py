"""
HTTP method tampering — test for access control bypass via alternate HTTP methods.
Some apps only check auth on GET/POST but not PUT/DELETE/PATCH.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-Method",
]


def test_methods(url, client=None, verbose=True):
    """Test all HTTP methods on a URL."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []
    results = {}

    for method in METHODS:
        try:
            resp = client.session.request(
                method, url, timeout=10, verify=False,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=False,
            )
            results[method] = {
                "status": resp.status_code,
                "size": len(resp.content),
                "headers": dict(resp.headers),
            }
            if verbose:
                print(f"    {method:8s} -> {resp.status_code} ({len(resp.content)}b)")
        except Exception:
            results[method] = None

    # Analyze results
    get_status = results.get("GET", {}).get("status") if results.get("GET") else None

    # Check for TRACE (XST vulnerability)
    trace_result = results.get("TRACE")
    if trace_result and trace_result["status"] == 200:
        findings.append(Finding(
            title="TRACE Method Enabled (XST)",
            severity="medium",
            description="TRACE method is enabled — potential Cross-Site Tracing (XST) attack vector.",
            url=url,
            evidence=f"TRACE {url} returned HTTP {trace_result['status']}",
            remediation="Disable TRACE method on the web server.",
        ))

    # Check for dangerous methods that shouldn't be publicly accessible
    for method in ["PUT", "DELETE", "PATCH"]:
        result = results.get(method)
        if result and result["status"] in (200, 201, 204):
            findings.append(Finding(
                title=f"{method} Method Allowed",
                severity="medium",
                description=f"HTTP {method} method returns success — may allow unauthorized data modification.",
                url=url,
                evidence=f"{method} {url} returned HTTP {result['status']}",
                remediation=f"Restrict {method} method to authenticated/authorized users only.",
            ))

    # Check if methods bypass auth (GET returns 401/403 but others return 200)
    if get_status in (401, 403):
        for method in ["POST", "PUT", "PATCH", "DELETE"]:
            result = results.get(method)
            if result and result["status"] == 200:
                findings.append(Finding(
                    title=f"Auth Bypass via {method} Method",
                    severity="high",
                    description=f"GET returns {get_status} but {method} returns 200 — potential authentication bypass.",
                    url=url,
                    evidence=f"GET -> {get_status}, {method} -> {result['status']}",
                    remediation="Enforce authentication/authorization on ALL HTTP methods, not just GET.",
                ))
                if verbose:
                    print(f"    [AUTH BYPASS] {method} bypasses {get_status}!")

    return findings, results


def test_method_override(url, client=None, verbose=True):
    """Test method override headers to bypass restrictions."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []

    # First check if GET is blocked
    resp = client.get(url)
    if not resp or resp.status_code not in (401, 403):
        return findings  # Not blocked, nothing to bypass

    blocked_status = resp.status_code

    for header in OVERRIDE_HEADERS:
        for method in ["PUT", "DELETE", "PATCH", "ADMIN"]:
            resp = client.post(
                url,
                headers={header: method},
            )
            if resp and resp.status_code == 200:
                findings.append(Finding(
                    title=f"Auth Bypass via {header}: {method}",
                    severity="high",
                    description=f"Using {header}: {method} header bypasses the {blocked_status} restriction.",
                    url=url,
                    evidence=f"POST with {header}: {method} returned 200 (normally {blocked_status})",
                    remediation=f"Don't trust {header} header from clients. Validate the actual HTTP method.",
                ))
                if verbose:
                    print(f"    [BYPASS] {header}: {method} -> 200 (was {blocked_status})")

    return findings


def scan_multiple(urls, verbose=True):
    all_findings = []
    client = HTTPClient(rate_limit=0.3, timeout=10)
    for url in urls:
        if verbose:
            print(f"\n  [{url[:80]}] testing methods...", flush=True)
        f, _ = test_methods(url, client, verbose)
        all_findings.extend(f)
        all_findings.extend(test_method_override(url, client, verbose))
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python method_tamper.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] HTTP method tampering: {url}\n")
    findings, results = test_methods(url)
    findings.extend(test_method_override(url))
    if not findings:
        print("\n  No method-based issues found")
