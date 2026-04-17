"""
Live host discovery — probe subdomains to find which ones respond.
Checks HTTP and HTTPS, grabs status code, title, and server header.
"""

import re
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient


def probe_host(host, client=None):
    """Probe a single host over HTTPS then HTTP. Returns info dict or None."""
    client = client or HTTPClient(timeout=8, retries=1)

    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        resp = client.get(url)
        if resp is not None:
            title = ""
            title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()[:100]

            return {
                "host": host,
                "url": url,
                "status": resp.status_code,
                "title": title,
                "server": resp.headers.get("Server", ""),
                "content_length": len(resp.content),
                "redirect": resp.url if resp.url != url else "",
            }
    return None


def check_hosts(hosts, max_workers=15, verbose=True):
    """Check multiple hosts concurrently. Returns list of live host dicts."""
    live = []
    client = HTTPClient(rate_limit=0.1, timeout=8, retries=1)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe_host, host, client): host for host in hosts}
        total = len(futures)
        done = 0

        for future in as_completed(futures):
            done += 1
            host = futures[future]
            try:
                result = future.result()
                if result:
                    live.append(result)
                    if verbose:
                        status = result["status"]
                        title = result["title"][:50] if result["title"] else "-"
                        print(f"  [{done}/{total}] {result['url']} [{status}] {title}")
                elif verbose and done % 20 == 0:
                    print(f"  [{done}/{total}] checking...", flush=True)
            except Exception:
                pass

    live.sort(key=lambda x: x["host"])
    return live


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python live_check.py <subdomains_file>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        hosts = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Probing {len(hosts)} hosts...\n")
    results = check_hosts(hosts)
    print(f"\n[+] Live hosts: {len(results)}/{len(hosts)}")
