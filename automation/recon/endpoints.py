"""
Endpoint discovery — pull URLs from Wayback Machine, Common Crawl, and URLScan.
Finds hidden paths, old endpoints, and interesting parameters.
"""

import re
import sys
import os
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient

INTERESTING_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".yaml", ".yml",
    ".conf", ".config", ".env", ".bak", ".old", ".backup", ".sql",
    ".log", ".txt", ".csv", ".xlsx", ".doc", ".pdf", ".zip", ".tar",
    ".gz", ".rar", ".git", ".svn", ".htaccess", ".htpasswd",
    ".graphql", ".wsdl", ".wadl", ".api",
}

INTERESTING_PARAMS = {
    "id", "page", "url", "redirect", "next", "return", "rurl", "file",
    "path", "folder", "dir", "search", "query", "q", "s", "keyword",
    "category", "user", "username", "email", "name", "password",
    "token", "key", "api_key", "apikey", "secret", "auth", "callback",
    "jsonp", "format", "type", "action", "cmd", "exec", "command",
    "upload", "download", "include", "require", "src", "source",
    "dest", "destination", "domain", "host", "port", "ip",
}


def from_wayback(domain, client=None, limit=5000):
    """Pull URLs from Wayback Machine CDX API."""
    client = client or HTTPClient(rate_limit=2, timeout=30)
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
    resp = client.get(url, verify=True)
    urls = set()
    if resp and resp.status_code == 200:
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if line:
                urls.add(line)
    return urls


def from_commoncrawl(domain, client=None):
    """Pull URLs from Common Crawl index."""
    client = client or HTTPClient(rate_limit=2, timeout=30)
    url = f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}/*&output=json&limit=2000"
    resp = client.get(url, verify=True)
    urls = set()
    if resp and resp.status_code == 200:
        for line in resp.text.strip().split("\n"):
            try:
                import json
                entry = json.loads(line)
                if "url" in entry:
                    urls.add(entry["url"])
            except Exception:
                continue
    return urls


def categorize_urls(urls):
    """Split URLs into categories for targeted testing."""
    categories = {
        "with_params": set(),
        "interesting_ext": set(),
        "api_endpoints": set(),
        "auth_endpoints": set(),
        "upload_endpoints": set(),
        "admin_endpoints": set(),
        "all_paths": set(),
        "interesting_params_found": set(),
    }

    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            params = parse_qs(parsed.query)

            categories["all_paths"].add(parsed.path)

            if params:
                categories["with_params"].add(url)
                for param in params:
                    if param.lower() in INTERESTING_PARAMS:
                        categories["interesting_params_found"].add(f"{param} -> {url}")

            ext = os.path.splitext(path)[1]
            if ext in INTERESTING_EXTENSIONS:
                categories["interesting_ext"].add(url)

            if "/api/" in path or "/v1/" in path or "/v2/" in path or "/v3/" in path or "/graphql" in path:
                categories["api_endpoints"].add(url)

            if any(kw in path for kw in ["/login", "/auth", "/signin", "/signup", "/register", "/oauth", "/sso", "/token"]):
                categories["auth_endpoints"].add(url)

            if any(kw in path for kw in ["/upload", "/import", "/attach"]):
                categories["upload_endpoints"].add(url)

            if any(kw in path for kw in ["/admin", "/dashboard", "/manage", "/panel", "/console", "/internal"]):
                categories["admin_endpoints"].add(url)

        except Exception:
            continue

    return categories


def discover(domain, verbose=True):
    """Full endpoint discovery for a domain."""
    client = HTTPClient(rate_limit=1, timeout=30)
    all_urls = set()

    sources = [
        ("Wayback Machine", from_wayback),
        ("Common Crawl", from_commoncrawl),
    ]

    for name, func in sources:
        if verbose:
            print(f"  [{name}] fetching...", end=" ", flush=True)
        try:
            urls = func(domain, client)
            all_urls.update(urls)
            if verbose:
                print(f"found {len(urls)}")
        except Exception as e:
            if verbose:
                print(f"error: {e}")

    categories = categorize_urls(all_urls)

    if verbose:
        print(f"\n  Total URLs: {len(all_urls)}")
        print(f"  With params: {len(categories['with_params'])}")
        print(f"  API endpoints: {len(categories['api_endpoints'])}")
        print(f"  Auth endpoints: {len(categories['auth_endpoints'])}")
        print(f"  Admin paths: {len(categories['admin_endpoints'])}")
        print(f"  Interesting extensions: {len(categories['interesting_ext'])}")
        print(f"  Interesting params: {len(categories['interesting_params_found'])}")

    return {"urls": sorted(all_urls), "categories": categories}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python endpoints.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    print(f"\n[*] Endpoint discovery: {domain}\n")
    results = discover(domain)
    print(f"\n[+] Total endpoints: {len(results['urls'])}")
