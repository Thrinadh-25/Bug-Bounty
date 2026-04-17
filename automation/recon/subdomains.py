"""
Subdomain enumeration — pulls from multiple free sources.
Sources: crt.sh, Wayback/URLScan, DNS brute (optional)
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient


def from_crtsh(domain, client=None):
    """Certificate transparency logs via crt.sh"""
    client = client or HTTPClient(rate_limit=2)
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = client.get(url, verify=True)
    subdomains = set()
    if resp and resp.status_code == 200:
        try:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub and sub.endswith(domain):
                        subdomains.add(sub)
        except (json.JSONDecodeError, KeyError):
            pass
    return subdomains


def from_hackertarget(domain, client=None):
    """HackerTarget free API"""
    client = client or HTTPClient(rate_limit=2)
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = client.get(url, verify=True)
    subdomains = set()
    if resp and resp.status_code == 200 and "error" not in resp.text.lower():
        for line in resp.text.strip().split("\n"):
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub and sub.endswith(domain):
                    subdomains.add(sub)
    return subdomains


def from_rapiddns(domain, client=None):
    """RapidDNS scraping"""
    client = client or HTTPClient(rate_limit=2)
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    resp = client.get(url, verify=True)
    subdomains = set()
    if resp and resp.status_code == 200:
        import re
        pattern = rf"([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(domain)}"
        matches = re.findall(pattern, resp.text)
        # Pull full matches from the HTML
        full_pattern = rf"[a-zA-Z0-9][-a-zA-Z0-9.]*\.{re.escape(domain)}"
        for match in re.findall(full_pattern, resp.text):
            sub = match.strip().lower()
            if sub.endswith(domain):
                subdomains.add(sub)
    return subdomains


def from_wayback(domain, client=None):
    """Wayback Machine — extract subdomains from archived URLs"""
    client = client or HTTPClient(rate_limit=2)
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
    resp = client.get(url, verify=True)
    subdomains = set()
    if resp and resp.status_code == 200:
        try:
            entries = resp.json()
            from urllib.parse import urlparse
            for entry in entries[1:]:  # skip header row
                try:
                    parsed = urlparse(entry[0])
                    host = parsed.hostname
                    if host and host.endswith(domain):
                        subdomains.add(host.lower())
                except Exception:
                    continue
        except (json.JSONDecodeError, IndexError):
            pass
    return subdomains


def enumerate(domain, verbose=True):
    """Run all subdomain sources and return deduplicated set."""
    client = HTTPClient(rate_limit=1, timeout=30)
    all_subs = set()
    all_subs.add(domain)

    sources = [
        ("crt.sh", from_crtsh),
        ("HackerTarget", from_hackertarget),
        ("RapidDNS", from_rapiddns),
        ("Wayback", from_wayback),
    ]

    for name, func in sources:
        if verbose:
            print(f"  [{name}] querying...", end=" ", flush=True)
        try:
            results = func(domain, client)
            all_subs.update(results)
            if verbose:
                print(f"found {len(results)}")
        except Exception as e:
            if verbose:
                print(f"error: {e}")

    return sorted(all_subs)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomains.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    print(f"\n[*] Enumerating subdomains for: {domain}\n")
    results = enumerate(domain)
    print(f"\n[+] Total unique subdomains: {len(results)}\n")
    for sub in results:
        print(f"  {sub}")
