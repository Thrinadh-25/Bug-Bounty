"""
Open redirect scanner — tests common redirect parameters for unvalidated redirects.
"""

import sys
import os
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Common redirect parameters
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "redir", "rurl",
    "next", "return", "return_url", "returnTo", "return_to", "returnUrl",
    "goto", "go", "to", "target", "destination", "dest", "out",
    "continue", "forward", "forward_url", "location", "link",
    "checkout_url", "callback", "callback_url", "follow", "ref",
    "site", "view", "path", "image_url", "logout", "login",
]

# Payloads to test
PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "https://evil.com/%2f..",
    "////evil.com",
    "https:evil.com",
    "http://evil.com",
    "https://evil.com@{host}",
    "https://{host}.evil.com",
    "//evil.com/%2F..",
    "/\\/evil.com",
    "/.evil.com",
    "https://evil.com#@{host}",
    "https://evil.com?.{host}",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
]


def test_url(url, client=None, verbose=True):
    """Test a single URL for open redirects on existing parameters."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    host = parsed.hostname

    # Test existing parameters that look like redirects
    redirect_params_found = [p for p in params if p.lower() in REDIRECT_PARAMS]

    for param in redirect_params_found:
        for payload_template in PAYLOADS[:8]:  # test top payloads
            payload = payload_template.replace("{host}", host or "")
            test_params = dict(params)
            test_params[param] = [payload]

            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

            resp = client.get(test_url, allow_redirects=False)
            if resp is None:
                continue

            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                loc_parsed = urlparse(location)
                if loc_parsed.hostname and loc_parsed.hostname != host and "evil.com" in loc_parsed.hostname:
                    findings.append(Finding(
                        title=f"Open Redirect via '{param}' parameter",
                        severity="medium",
                        description=f"The '{param}' parameter redirects to an attacker-controlled domain without validation.",
                        url=test_url,
                        evidence=f"Request: {test_url}\nRedirect Location: {location}",
                        remediation="Validate redirect URLs against an allowlist. Only allow relative paths or same-domain redirects.",
                    ))
                    if verbose:
                        print(f"    [FOUND] {param}={payload} -> {location}")
                    break  # found vuln for this param, move on

    return findings


def fuzz_params(base_url, client=None, verbose=True):
    """Test adding common redirect parameters to a URL."""
    client = client or HTTPClient(timeout=10, retries=1)
    findings = []
    parsed = urlparse(base_url)
    host = parsed.hostname

    for param in REDIRECT_PARAMS:
        payload = "https://evil.com"
        test_params = {param: payload}
        query = urlencode(test_params)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

        resp = client.get(test_url, allow_redirects=False)
        if resp is None:
            continue

        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and location:
            loc_parsed = urlparse(location)
            if loc_parsed.hostname and "evil.com" in loc_parsed.hostname:
                findings.append(Finding(
                    title=f"Open Redirect via '{param}' parameter",
                    severity="medium",
                    description=f"Adding '{param}' parameter causes redirect to attacker domain.",
                    url=test_url,
                    evidence=f"Request: {test_url}\nRedirect Location: {location}",
                    remediation="Validate redirect URLs server-side. Use an allowlist.",
                ))
                if verbose:
                    print(f"    [FOUND] ?{param}=evil.com -> {location}")

    return findings


def scan_multiple(urls, verbose=True):
    """Scan multiple URLs for open redirect issues."""
    client = HTTPClient(rate_limit=0.3, timeout=10)
    all_findings = []

    for url in urls:
        if verbose:
            print(f"  [{url}] testing redirects...", flush=True)
        findings = test_url(url, client, verbose)
        findings.extend(fuzz_params(url, client, verbose))
        all_findings.extend(findings)

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python open_redirect.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] Open redirect scan: {url}\n")
    findings = test_url(url)
    findings.extend(fuzz_params(url))
    if not findings:
        print("  No open redirects found")
