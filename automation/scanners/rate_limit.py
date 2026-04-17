"""
Rate limit tester — check if critical endpoints have rate limiting.
Missing rate limits on login, registration, password reset = vulnerability.
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Endpoints that MUST have rate limiting
CRITICAL_ENDPOINTS = {
    "login": ["/login", "/signin", "/auth", "/api/login", "/api/auth",
              "/api/v1/login", "/api/v1/auth", "/oauth/token"],
    "register": ["/register", "/signup", "/api/register", "/api/v1/register"],
    "password_reset": ["/reset", "/forgot", "/forgot-password", "/api/reset-password",
                       "/api/v1/forgot-password", "/password/reset"],
    "otp": ["/verify", "/verify-otp", "/api/verify", "/otp", "/2fa"],
    "api": ["/api/", "/graphql"],
}


def test_rate_limit(url, method="GET", num_requests=30, data=None, verbose=True):
    """
    Send rapid requests to test for rate limiting.
    Returns: (is_limited, details)
    """
    client = HTTPClient(rate_limit=0, timeout=10, retries=0)  # No rate limit on our side
    responses = []
    blocked_at = None

    for i in range(num_requests):
        if method == "POST":
            resp = client.post(url, json=data or {"test": "test"})
        else:
            resp = client.get(url)

        if resp:
            responses.append({
                "request_num": i + 1,
                "status": resp.status_code,
                "size": len(resp.content),
                "time": time.time(),
            })

            if resp.status_code == 429:
                blocked_at = i + 1
                retry_after = resp.headers.get("Retry-After", "not specified")
                if verbose:
                    print(f"    Rate limited at request #{i+1} (Retry-After: {retry_after})")
                break

            if resp.status_code in (403, 503) and i > 5:
                # Might be WAF rate limiting
                blocked_at = i + 1
                if verbose:
                    print(f"    Blocked at request #{i+1} (HTTP {resp.status_code})")
                break
        else:
            # Connection failed — might be rate limited at network level
            if i > 5:
                blocked_at = i + 1
                break

    return {
        "is_limited": blocked_at is not None,
        "blocked_at": blocked_at,
        "total_sent": len(responses),
        "responses": responses,
    }


def scan_url(url, verbose=True):
    """Test a specific URL for rate limiting."""
    client = HTTPClient(timeout=10)
    findings = []

    # Check if the URL exists first
    resp = client.get(url)
    if not resp or resp.status_code == 404:
        return findings

    if verbose:
        print(f"  Testing {url} ({30} rapid requests)...", flush=True)

    # Determine method based on endpoint
    method = "POST" if any(kw in url.lower() for kw in ["login", "auth", "register", "reset", "verify"]) else "GET"

    result = test_rate_limit(url, method=method, num_requests=30, verbose=verbose)

    if not result["is_limited"]:
        # Determine severity based on endpoint type
        url_lower = url.lower()
        if any(kw in url_lower for kw in ["login", "auth", "signin"]):
            severity = "high"
            desc = "Login endpoint has no rate limiting — brute force attacks possible."
        elif any(kw in url_lower for kw in ["reset", "forgot", "password"]):
            severity = "high"
            desc = "Password reset has no rate limiting — allows email bombing and token brute force."
        elif any(kw in url_lower for kw in ["otp", "verify", "2fa"]):
            severity = "critical"
            desc = "OTP/2FA verification has no rate limiting — OTP brute force possible."
        elif any(kw in url_lower for kw in ["register", "signup"]):
            severity = "medium"
            desc = "Registration has no rate limiting — mass account creation possible."
        else:
            severity = "low"
            desc = "Endpoint has no rate limiting."

        findings.append(Finding(
            title=f"No Rate Limiting on {url.split('/')[-1]}",
            severity=severity,
            description=desc,
            url=url,
            evidence=f"Sent {result['total_sent']} rapid requests without being rate limited",
            remediation="Implement rate limiting. Use progressive delays, CAPTCHAs, or account lockout.",
        ))
        if verbose:
            print(f"    [{severity.upper()}] No rate limiting detected!")
    elif verbose:
        print(f"    Rate limited at request #{result['blocked_at']} (good)")

    return findings


def discover_and_test(base_url, verbose=True):
    """Discover critical endpoints and test each for rate limiting."""
    client = HTTPClient(timeout=8, retries=1)
    findings = []
    tested = set()

    for category, paths in CRITICAL_ENDPOINTS.items():
        for path in paths:
            url = base_url.rstrip("/") + path
            if url in tested:
                continue
            tested.add(url)

            resp = client.get(url)
            if resp and resp.status_code not in (404, 405):
                if verbose:
                    print(f"\n  Found: {url} [{resp.status_code}]")
                findings.extend(scan_url(url, verbose))

    return findings


def scan_multiple(urls, verbose=True):
    all_findings = []
    for url in urls:
        if verbose:
            print(f"\n  [{url}] rate limit scan...", flush=True)
        all_findings.extend(discover_and_test(url, verbose))
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python rate_limit.py <base_url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] Rate limit scan: {url}\n")
    discover_and_test(url)
