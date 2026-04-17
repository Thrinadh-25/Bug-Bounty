"""
Security header analysis — checks for missing/misconfigured security headers.
Almost always produces findings. Low-hanging fruit.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS not set — browser won't enforce HTTPS. Allows SSL stripping attacks.",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "checks": {
            "max-age": lambda v: "max-age" in v.lower() and int(
                v.lower().split("max-age=")[1].split(";")[0].strip()
            ) >= 31536000 if "max-age" in v.lower() else False,
        },
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "No CSP header — XSS attacks have no browser-side mitigation.",
        "remediation": "Implement a Content-Security-Policy header. Start with report-only mode.",
        "checks": {
            "unsafe-inline": lambda v: "unsafe-inline" not in v,
            "unsafe-eval": lambda v: "unsafe-eval" not in v,
            "wildcard_src": lambda v: "'*'" not in v.split("script-src")[1] if "script-src" in v else True,
        },
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options not set — browser may MIME-sniff responses.",
        "remediation": "Add X-Content-Type-Options: nosniff",
        "checks": {},
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options not set — page can be framed (clickjacking risk).",
        "remediation": "Add X-Frame-Options: DENY (or SAMEORIGIN if framing needed)",
        "checks": {},
    },
    "X-XSS-Protection": {
        "severity": "info",
        "description": "X-XSS-Protection not set. Modern browsers rely on CSP, but legacy support matters.",
        "remediation": "Add X-XSS-Protection: 1; mode=block (or 0 if CSP is solid)",
        "checks": {},
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "No Referrer-Policy — full URL may leak to external sites via Referer header.",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "checks": {},
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "No Permissions-Policy — browser features like camera/microphone not restricted.",
        "remediation": "Add Permissions-Policy to restrict unnecessary browser features.",
        "checks": {},
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "info",
        "description": "Server header leaks software version information.",
    },
    "X-Powered-By": {
        "severity": "low",
        "description": "X-Powered-By header leaks backend technology — aids targeted attacks.",
    },
    "X-AspNet-Version": {
        "severity": "low",
        "description": "X-AspNet-Version header leaks ASP.NET version.",
    },
    "X-AspNetMvc-Version": {
        "severity": "low",
        "description": "X-AspNetMvc-Version header leaks MVC framework version.",
    },
}


def analyze(url, client=None):
    """Analyze security headers for a single URL. Returns list of Findings."""
    client = client or HTTPClient(timeout=10)
    resp = client.get(url)
    if not resp:
        return []

    findings = []
    headers = resp.headers

    # Check for missing security headers
    for header, config in SECURITY_HEADERS.items():
        value = headers.get(header, "")
        if not value:
            findings.append(Finding(
                title=f"Missing {header}",
                severity=config["severity"],
                description=config["description"],
                url=url,
                evidence=f"Header '{header}' not present in response",
                remediation=config["remediation"],
            ))
        else:
            # Check for weak configurations
            for check_name, check_func in config.get("checks", {}).items():
                try:
                    if not check_func(value):
                        findings.append(Finding(
                            title=f"Weak {header} ({check_name})",
                            severity="low",
                            description=f"{header} is set but contains weak configuration: {check_name}",
                            url=url,
                            evidence=f"{header}: {value}",
                            remediation=config["remediation"],
                        ))
                except Exception:
                    pass

    # Check for info-leaking headers
    for header, config in DANGEROUS_HEADERS.items():
        value = headers.get(header, "")
        if value:
            findings.append(Finding(
                title=f"Information Disclosure via {header}",
                severity=config["severity"],
                description=config["description"],
                url=url,
                evidence=f"{header}: {value}",
                remediation=f"Remove or suppress the {header} header.",
            ))

    # Check for CORS wildcard in headers
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        findings.append(Finding(
            title="CORS Wildcard Origin",
            severity="low",
            description="Access-Control-Allow-Origin is set to '*' — any site can make cross-origin requests.",
            url=url,
            evidence=f"Access-Control-Allow-Origin: {acao}",
            remediation="Restrict Access-Control-Allow-Origin to specific trusted origins.",
        ))

    return findings


def scan_multiple(urls, verbose=True):
    """Scan multiple URLs for header issues."""
    client = HTTPClient(rate_limit=0.3, timeout=10)
    all_findings = []

    for url in urls:
        if verbose:
            print(f"  [{url}] checking headers...", flush=True)
        findings = analyze(url, client)
        all_findings.extend(findings)
        if verbose and findings:
            for f in findings:
                print(f"    [{f.severity.upper()}] {f.title}")

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python headers.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] Header analysis: {url}\n")
    findings = analyze(url)
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}")
        print(f"    {f.evidence}")
