"""
Host header injection scanner — detect web cache poisoning, password reset poisoning,
and SSRF via manipulated Host headers.
"""

import sys
import os
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

CANARY_HOST = "evil-7x3k.com"


def test_host_injection(url, client=None, verbose=True):
    """Test various Host header manipulation techniques."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []
    parsed = urlparse(url)
    original_host = parsed.hostname

    tests = [
        # Overwrite Host header
        {
            "name": "Host Override",
            "headers": {"Host": CANARY_HOST},
            "check": "header_reflected",
        },
        # X-Forwarded-Host
        {
            "name": "X-Forwarded-Host",
            "headers": {"X-Forwarded-Host": CANARY_HOST},
            "check": "body_reflected",
        },
        # X-Host
        {
            "name": "X-Host",
            "headers": {"X-Host": CANARY_HOST},
            "check": "body_reflected",
        },
        # X-Forwarded-Server
        {
            "name": "X-Forwarded-Server",
            "headers": {"X-Forwarded-Server": CANARY_HOST},
            "check": "body_reflected",
        },
        # Forwarded header (RFC 7239)
        {
            "name": "Forwarded header",
            "headers": {"Forwarded": f"host={CANARY_HOST}"},
            "check": "body_reflected",
        },
        # Host with port
        {
            "name": "Host with port injection",
            "headers": {"Host": f"{original_host}:{CANARY_HOST}"},
            "check": "body_reflected",
        },
        # Double Host (some servers take the second)
        {
            "name": "Duplicate Host",
            "headers": {"Host": original_host, "X-Forwarded-Host": CANARY_HOST},
            "check": "body_reflected",
        },
        # Absolute URL with different host
        {
            "name": "Absolute URL override",
            "headers": {"Host": CANARY_HOST},
            "check": "redirect_poisoned",
        },
    ]

    # Get baseline
    baseline = client.get(url)
    if not baseline:
        return findings

    for test in tests:
        resp = client.get(url, headers=test["headers"])
        if not resp:
            continue

        found = False

        if test["check"] == "body_reflected" and CANARY_HOST in resp.text:
            found = True
            evidence = f"Header: {test['headers']}\nCanary '{CANARY_HOST}' found in response body"

        elif test["check"] == "header_reflected":
            location = resp.headers.get("Location", "")
            if CANARY_HOST in location:
                found = True
                evidence = f"Header: {test['headers']}\nLocation header: {location}"

        elif test["check"] == "redirect_poisoned":
            location = resp.headers.get("Location", "")
            if CANARY_HOST in location:
                found = True
                evidence = f"Header: {test['headers']}\nPoisoned redirect: {location}"

        if found:
            severity = "high"
            desc = (
                f"Host header injection via {test['name']}. "
                f"The server uses the attacker-controlled Host value in its response. "
                f"This can lead to web cache poisoning, password reset poisoning, or SSRF."
            )

            findings.append(Finding(
                title=f"Host Header Injection: {test['name']}",
                severity=severity,
                description=desc,
                url=url,
                evidence=evidence,
                remediation=(
                    "Ignore or validate the Host header. Use a server-configured hostname "
                    "instead of trusting the Host header for URL generation. "
                    "Strip X-Forwarded-Host if not from a trusted proxy."
                ),
            ))
            if verbose:
                print(f"    [{severity.upper()}] {test['name']}: {CANARY_HOST} reflected!")

    return findings


def test_password_reset_poisoning(url, client=None, verbose=True):
    """
    Specifically test password reset for host header poisoning.
    This is a targeted test — pass the password reset URL.
    """
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []

    headers_to_test = [
        {"X-Forwarded-Host": CANARY_HOST},
        {"Host": CANARY_HOST},
        {"X-Host": CANARY_HOST},
    ]

    for headers in headers_to_test:
        resp = client.post(url, headers=headers)
        if resp and CANARY_HOST in resp.text:
            findings.append(Finding(
                title="Password Reset Poisoning",
                severity="high",
                description="The password reset mechanism uses the Host header to generate reset links. An attacker can steal reset tokens.",
                url=url,
                evidence=f"Headers: {headers}\nCanary found in reset response",
                remediation="Hard-code the application URL in password reset emails. Never use the Host header.",
            ))
            if verbose:
                print(f"    [HIGH] Password reset poisoning!")
            break

    return findings


def scan_multiple(urls, verbose=True):
    all_findings = []
    client = HTTPClient(rate_limit=0.5, timeout=10)
    for url in urls:
        if verbose:
            print(f"  [{url[:80]}] testing Host header...", flush=True)
        all_findings.extend(test_host_injection(url, client, verbose))
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python host_header.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] Host header injection scan: {url}\n")
    findings = test_host_injection(url)
    if not findings:
        print("  No host header injection found")
