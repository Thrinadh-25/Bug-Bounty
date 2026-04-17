"""
Virtual host discovery — find hidden vhosts on the same IP.
Sends requests with different Host headers to detect virtual hosts.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

COMMON_VHOSTS = [
    "admin", "api", "app", "beta", "blog", "cdn", "ci", "cms",
    "cpanel", "dashboard", "db", "demo", "dev", "docs", "email",
    "ftp", "git", "gitlab", "grafana", "graphql", "help", "internal",
    "intranet", "jenkins", "jira", "kibana", "lab", "legacy", "login",
    "m", "mail", "manage", "manager", "monitor", "mysql", "new",
    "old", "panel", "phpmyadmin", "portal", "preview", "prod",
    "prometheus", "proxy", "qa", "redis", "remote", "repo",
    "sandbox", "secure", "shop", "sso", "stage", "staging",
    "static", "status", "store", "support", "test", "testing",
    "tools", "uat", "vpn", "webmail", "wiki", "www",
]


def discover(target_ip, domain, wordlist=None, verbose=True):
    """
    Discover virtual hosts by fuzzing the Host header.
    target_ip: IP or main hostname to connect to
    domain: base domain to append vhost prefixes to
    """
    client = HTTPClient(rate_limit=0.2, timeout=8, retries=1)

    words = COMMON_VHOSTS
    if wordlist and os.path.exists(wordlist):
        with open(wordlist) as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # Get baseline response (with the real Host header)
    base_url = f"https://{target_ip}" if target_ip != domain else f"https://{domain}"
    baseline = client.get(base_url, headers={"Host": domain})
    if not baseline:
        # Try HTTP
        base_url = f"http://{target_ip}" if target_ip != domain else f"http://{domain}"
        baseline = client.get(base_url, headers={"Host": domain})
    if not baseline:
        if verbose:
            print("  Could not get baseline response")
        return []

    baseline_size = len(baseline.content)
    baseline_status = baseline.status_code

    # Also get a definitely-wrong vhost for comparison
    fake_resp = client.get(base_url, headers={"Host": f"doesnotexist7x3k.{domain}"})
    fake_size = len(fake_resp.content) if fake_resp else 0

    found = []

    for word in words:
        vhost = f"{word}.{domain}"
        resp = client.get(base_url, headers={"Host": vhost})
        if not resp:
            continue

        resp_size = len(resp.content)
        is_different = (
            resp.status_code != baseline_status
            or abs(resp_size - baseline_size) > 100
        )
        is_not_fake = abs(resp_size - fake_size) > 100 if fake_resp else True

        if is_different and is_not_fake and resp.status_code < 500:
            found.append({
                "vhost": vhost,
                "status": resp.status_code,
                "size": resp_size,
                "baseline_diff": resp_size - baseline_size,
            })
            if verbose:
                print(f"    [FOUND] {vhost} [{resp.status_code}] ({resp_size}b)")

    return found


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python vhost_discover.py <target_ip> <domain>")
        print("Example: python vhost_discover.py 93.184.216.34 example.com")
        sys.exit(1)
    print(f"\n[*] VHost discovery: {sys.argv[1]} ({sys.argv[2]})\n")
    discover(sys.argv[1], sys.argv[2])
