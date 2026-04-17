"""
Subdomain takeover checker — detect dangling DNS records pointing to deprovisioned services.
Can be critical severity finding.
"""

import sys
import os
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Service fingerprints: CNAME pattern -> (service name, response fingerprint for confirmation)
TAKEOVER_FINGERPRINTS = {
    "amazonaws.com": {
        "service": "AWS S3",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
    },
    "s3.amazonaws.com": {
        "service": "AWS S3",
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
    },
    "elasticbeanstalk.com": {
        "service": "AWS Elastic Beanstalk",
        "fingerprints": ["NXDOMAIN"],
        "severity": "high",
    },
    "github.io": {
        "service": "GitHub Pages",
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
        "severity": "high",
    },
    "herokuapp.com": {
        "service": "Heroku",
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages"],
        "severity": "high",
    },
    "herokudns.com": {
        "service": "Heroku",
        "fingerprints": ["No such app", "no-such-app"],
        "severity": "high",
    },
    "azure-api.net": {
        "service": "Azure",
        "fingerprints": ["NXDOMAIN", "404 Web Site not found"],
        "severity": "high",
    },
    "azurewebsites.net": {
        "service": "Azure App Service",
        "fingerprints": ["404 Web Site not found", "not found"],
        "severity": "high",
    },
    "cloudapp.net": {
        "service": "Azure Cloud",
        "fingerprints": ["NXDOMAIN"],
        "severity": "high",
    },
    "trafficmanager.net": {
        "service": "Azure Traffic Manager",
        "fingerprints": ["NXDOMAIN"],
        "severity": "high",
    },
    "zendesk.com": {
        "service": "Zendesk",
        "fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "severity": "medium",
    },
    "readme.io": {
        "service": "ReadMe",
        "fingerprints": ["Project doesnt exist"],
        "severity": "medium",
    },
    "ghost.io": {
        "service": "Ghost",
        "fingerprints": ["The thing you were looking for is no longer here"],
        "severity": "medium",
    },
    "shopify.com": {
        "service": "Shopify",
        "fingerprints": ["Sorry, this shop is currently unavailable", "only-resolve-dns"],
        "severity": "high",
    },
    "surge.sh": {
        "service": "Surge.sh",
        "fingerprints": ["project not found"],
        "severity": "medium",
    },
    "pantheon.io": {
        "service": "Pantheon",
        "fingerprints": ["404 error unknown site"],
        "severity": "medium",
    },
    "tumblr.com": {
        "service": "Tumblr",
        "fingerprints": ["There's nothing here", "Whatever you were looking for"],
        "severity": "medium",
    },
    "wordpress.com": {
        "service": "WordPress.com",
        "fingerprints": ["Do you want to register"],
        "severity": "medium",
    },
    "cargocollective.com": {
        "service": "Cargo",
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "fly.dev": {
        "service": "Fly.io",
        "fingerprints": ["NXDOMAIN"],
        "severity": "medium",
    },
    "netlify.app": {
        "service": "Netlify",
        "fingerprints": ["Not Found - Request ID"],
        "severity": "high",
    },
    "vercel.app": {
        "service": "Vercel",
        "fingerprints": ["DEPLOYMENT_NOT_FOUND"],
        "severity": "high",
    },
    "unbouncepages.com": {
        "service": "Unbounce",
        "fingerprints": ["The requested URL was not found"],
        "severity": "medium",
    },
}


def get_cname(subdomain):
    """Resolve CNAME for a subdomain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        pass

    # Fallback: try socket
    try:
        result = socket.getaddrinfo(subdomain, None)
        return result[0][4][0] if result else None
    except socket.gaierror:
        return "NXDOMAIN"
    except Exception:
        return None


def check_subdomain(subdomain, client=None):
    """Check a single subdomain for takeover potential. Returns Finding or None."""
    client = client or HTTPClient(timeout=10, retries=1)

    cname = get_cname(subdomain)
    if not cname:
        return None

    # Check NXDOMAIN — DNS doesn't resolve, possible takeover
    if cname == "NXDOMAIN":
        return Finding(
            title=f"Potential Subdomain Takeover (NXDOMAIN): {subdomain}",
            severity="medium",
            description=f"Subdomain {subdomain} has a DNS record but doesn't resolve. Could indicate dangling record.",
            url=subdomain,
            evidence=f"DNS lookup: NXDOMAIN",
            remediation="Remove the DNS record if the service is no longer in use.",
        )

    # Check CNAME against known vulnerable services
    cname_lower = cname.lower()
    for pattern, config in TAKEOVER_FINGERPRINTS.items():
        if pattern in cname_lower:
            # Confirm by checking HTTP response
            for scheme in ["https", "http"]:
                resp = client.get(f"{scheme}://{subdomain}")
                if resp:
                    body = resp.text[:5000]
                    for fp in config["fingerprints"]:
                        if fp == "NXDOMAIN":
                            continue
                        if fp.lower() in body.lower():
                            return Finding(
                                title=f"Subdomain Takeover: {subdomain} ({config['service']})",
                                severity=config["severity"],
                                description=(
                                    f"Subdomain {subdomain} has a CNAME pointing to {cname} ({config['service']}), "
                                    f"and the service shows a deprovisioned response. An attacker can claim this."
                                ),
                                url=f"{scheme}://{subdomain}",
                                evidence=f"CNAME: {cname}\nFingerprint matched: {fp}",
                                remediation="Remove the DNS record or reclaim the service.",
                            )
                    break  # checked this service, move on

    return None


def scan(subdomains, verbose=True):
    """Check multiple subdomains for takeover. Returns list of Findings."""
    client = HTTPClient(rate_limit=0.3, timeout=10, retries=1)
    findings = []

    for sub in subdomains:
        if verbose:
            print(f"  [{sub}] checking...", end=" ", flush=True)
        finding = check_subdomain(sub, client)
        if finding:
            findings.append(finding)
            if verbose:
                print(f"VULNERABLE! ({finding.title})")
        elif verbose:
            print("ok")

    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python takeover.py <subdomains_file>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        subs = [line.strip() for line in f if line.strip()]
    print(f"\n[*] Checking {len(subs)} subdomains for takeover...\n")
    findings = scan(subs)
    print(f"\n[+] Vulnerable: {len(findings)}")
