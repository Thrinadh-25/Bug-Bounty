"""
Directory/file brute forcing — find hidden paths, admin panels, backup files.
Uses ffuf if available, falls back to Python threaded brute force.
"""

import subprocess
import sys
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Sensitive files that should never be public
SENSITIVE_FILES = [
    ".env", ".git/config", ".git/HEAD", ".gitignore",
    ".htaccess", ".htpasswd", ".svn/entries",
    "wp-config.php.bak", "web.config", "config.php.bak",
    "database.yml", "settings.py", "config.json",
    "composer.json", "package.json", "Gemfile",
    ".DS_Store", "Thumbs.db",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".well-known/security.txt",
    "server-status", "server-info",
    "phpinfo.php", "info.php", "test.php",
    "elmah.axd", "trace.axd",
    "backup.sql", "dump.sql", "database.sql",
    "backup.zip", "backup.tar.gz", "site.tar.gz",
    "debug", "debug/default/view",
    "actuator", "actuator/env", "actuator/health",
    "api/swagger.json", "swagger/v1/swagger.json",
    "api-docs", "graphql", "graphiql",
    ".dockerenv", "Dockerfile",
    "wp-login.php", "wp-admin",
    "admin", "administrator", "login",
    "console", "dashboard", "manager",
    "phpmyadmin", "adminer", "adminer.php",
]


def ffuf_available():
    try:
        subprocess.run(["ffuf", "-V"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def ffuf_scan(url, wordlist, extra_args="", timeout=300):
    """Run ffuf for directory brute forcing."""
    cmd = [
        "ffuf", "-u", f"{url.rstrip('/')}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,204,301,302,307,401,403,405,500",
        "-fc", "404",
        "-t", "40",
        "-timeout", "10",
        "-o", "/tmp/ffuf_out.json",
        "-of", "json",
        "-s",  # silent
    ]
    if extra_args:
        cmd.extend(extra_args.split())

    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        import json
        if os.path.exists("/tmp/ffuf_out.json"):
            with open("/tmp/ffuf_out.json") as f:
                data = json.load(f)
            os.remove("/tmp/ffuf_out.json")
            return data.get("results", [])
    except Exception:
        pass
    return []


def python_brute(url, wordlist_path=None, words=None, max_workers=20, verbose=True):
    """Python-based directory brute forcing."""
    client = HTTPClient(rate_limit=0.05, timeout=8, retries=1)

    if words is None:
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            words = SENSITIVE_FILES

    base_url = url.rstrip("/")
    results = []

    # Get baseline 404
    resp_404 = client.get(f"{base_url}/thisdoesnotexist_7x3k")
    baseline_404_size = len(resp_404.content) if resp_404 else 0

    def check_path(word):
        test_url = f"{base_url}/{word}"
        resp = client.get(test_url, allow_redirects=False)
        if resp is None:
            return None
        if resp.status_code == 404:
            return None
        # Filter soft 404s by comparing response size
        if resp.status_code == 200 and baseline_404_size > 0:
            if abs(len(resp.content) - baseline_404_size) < 50:
                return None
        return {
            "path": word,
            "url": test_url,
            "status": resp.status_code,
            "size": len(resp.content),
            "redirect": resp.headers.get("Location", ""),
        }

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_path, w): w for w in words}
        done = 0
        total = len(futures)
        for future in as_completed(futures):
            done += 1
            try:
                result = future.result()
                if result:
                    results.append(result)
                    if verbose:
                        redir = f" -> {result['redirect']}" if result['redirect'] else ""
                        print(f"    [{result['status']}] /{result['path']} ({result['size']}b){redir}")
                elif verbose and done % 50 == 0:
                    print(f"    [{done}/{total}]...", flush=True)
            except Exception:
                pass

    results.sort(key=lambda x: x["status"])
    return results


def brute(url, wordlist=None, verbose=True):
    """Smart directory brute force — uses ffuf if available."""
    default_wordlist = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "wordlists", "common_dirs.txt"
    )
    kali_wordlist = "/usr/share/wordlists/dirb/common.txt"
    seclists_wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"

    # Pick best available wordlist
    if wordlist and os.path.exists(wordlist):
        wl = wordlist
    elif os.path.exists(seclists_wordlist):
        wl = seclists_wordlist
    elif os.path.exists(kali_wordlist):
        wl = kali_wordlist
    else:
        wl = default_wordlist

    if verbose:
        print(f"  Wordlist: {wl}")

    if ffuf_available():
        if verbose:
            print("  Engine: ffuf")
        ffuf_results = ffuf_scan(url, wl)
        results = []
        for r in ffuf_results:
            results.append({
                "path": r.get("input", {}).get("FUZZ", ""),
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "size": r.get("length", 0),
                "redirect": r.get("redirectlocation", ""),
            })
        if verbose:
            for r in results:
                print(f"    [{r['status']}] /{r['path']} ({r['size']}b)")
        return results
    else:
        if verbose:
            print("  Engine: python (install ffuf for faster results)")
        return python_brute(url, wl, verbose=verbose)


def sensitive_file_check(url, verbose=True):
    """Specifically check for sensitive/dangerous files."""
    if verbose:
        print(f"  Checking sensitive files on {url}...")

    results = python_brute(url, words=SENSITIVE_FILES, verbose=verbose)
    findings = []

    for r in results:
        path = r["path"]
        severity = "info"

        if any(s in path for s in [".env", ".git", "config", "database", "backup", ".sql"]):
            severity = "high"
        elif any(s in path for s in [".htpasswd", "phpinfo", "actuator/env", "debug"]):
            severity = "high"
        elif any(s in path for s in ["admin", "console", "dashboard", "swagger", "graphql"]):
            severity = "medium"
        elif any(s in path for s in [".htaccess", "robots.txt", "sitemap", "server-status"]):
            severity = "low"

        findings.append(Finding(
            title=f"Exposed: /{path}",
            severity=severity,
            description=f"Sensitive file or path found: /{path} (HTTP {r['status']})",
            url=r["url"],
            evidence=f"HTTP {r['status']} - {r['size']} bytes",
            remediation="Restrict access to sensitive files. Block in web server config or remove from production.",
        ))

    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dir_brute.py <url> [wordlist]")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    wl = sys.argv[2] if len(sys.argv) > 2 else None
    print(f"\n[*] Directory brute force: {url}\n")
    results = brute(url, wl)
    print(f"\n[+] Found: {len(results)} paths")
