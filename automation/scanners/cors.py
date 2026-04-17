"""
CORS misconfiguration scanner — tests for exploitable cross-origin policies.
Common bug bounty finding, often medium-high severity.
"""

import sys
import os
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding


def generate_origins(target_url):
    """Generate malicious origins to test CORS against."""
    parsed = urlparse(target_url)
    domain = parsed.hostname
    scheme = parsed.scheme

    origins = [
        # Reflected origin (most common vuln)
        ("Reflected Origin", "https://evil.com"),
        # Null origin (exploitable via sandboxed iframe)
        ("Null Origin", "null"),
        # Subdomain of attacker
        ("Attacker Subdomain", f"https://{domain}.evil.com"),
        # Prefix match bypass
        ("Prefix Bypass", f"https://{domain}evil.com"),
        # Suffix match bypass
        ("Suffix Bypass", f"https://evil{domain}"),
        # Subdomain takeover scenario
        ("Subdomain", f"https://test.{domain}"),
        # HTTP downgrade
        ("HTTP Downgrade", f"http://{domain}"),
        # Special chars bypass
        ("Underscore Bypass", f"https://{domain}_.evil.com"),
        ("Backtick Bypass", f"https://{domain}%60.evil.com"),
    ]
    return origins


def test_cors(url, client=None, verbose=True):
    """Test a URL for CORS misconfigurations. Returns list of Findings."""
    client = client or HTTPClient(timeout=10)
    findings = []

    # First, check default response
    resp = client.get(url)
    if not resp:
        return findings

    default_acao = resp.headers.get("Access-Control-Allow-Origin", "")
    default_acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if default_acao == "*":
        sev = "medium" if default_acac == "true" else "low"
        findings.append(Finding(
            title="CORS Wildcard Origin",
            severity=sev,
            description="Access-Control-Allow-Origin is set to '*'. Any website can read responses.",
            url=url,
            evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: {default_acac}",
            remediation="Restrict to specific trusted origins. Never combine '*' with credentials.",
        ))

    # Test each malicious origin
    test_origins = generate_origins(url)
    for test_name, origin in test_origins:
        if origin == "null":
            headers = {"Origin": "null"}
        else:
            headers = {"Origin": origin}

        resp = client.get(url, headers=headers)
        if not resp:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        reflected = False
        if origin == "null" and acao == "null":
            reflected = True
        elif acao == origin:
            reflected = True

        if reflected:
            if acac == "true":
                severity = "high"
                desc = (
                    f"CORS reflects arbitrary origin WITH credentials. "
                    f"An attacker at {origin} can steal authenticated data."
                )
            else:
                severity = "medium"
                desc = (
                    f"CORS reflects origin {origin} without credential support. "
                    f"Cross-origin data reading possible for non-authenticated content."
                )

            findings.append(Finding(
                title=f"CORS Misconfiguration: {test_name}",
                severity=severity,
                description=desc,
                url=url,
                evidence=(
                    f"Request Origin: {origin}\n"
                    f"Response Access-Control-Allow-Origin: {acao}\n"
                    f"Response Access-Control-Allow-Credentials: {acac}"
                ),
                remediation=(
                    "Validate the Origin header against a strict allowlist. "
                    "Never reflect arbitrary origins, especially with Allow-Credentials: true."
                ),
            ))

            if verbose:
                print(f"    [{severity.upper()}] {test_name}: origin {origin} reflected!")

    return findings


def scan_multiple(urls, verbose=True):
    """Test multiple URLs for CORS issues."""
    client = HTTPClient(rate_limit=0.5, timeout=10)
    all_findings = []

    for url in urls:
        if verbose:
            print(f"  [{url}] testing CORS...", flush=True)
        findings = test_cors(url, client, verbose)
        all_findings.extend(findings)

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cors.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] CORS scan: {url}\n")
    findings = test_cors(url)
    if not findings:
        print("  No CORS issues found")
    for f in findings:
        print(f"\n  [{f.severity.upper()}] {f.title}")
        print(f"  {f.evidence}")
