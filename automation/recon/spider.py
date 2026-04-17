"""
Web spider/crawler — recursively crawl a target to discover all pages,
forms, endpoints, and inputs. Respects scope.
"""

import re
import sys
import os
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.scope import ScopeChecker


def extract_links(html, base_url):
    """Extract all links from HTML."""
    links = set()
    patterns = [
        r'href=["\']([^"\'#]+)',
        r'src=["\']([^"\'#]+)',
        r'action=["\']([^"\'#]+)',
        r'url\(["\']?([^"\')\s]+)',
        r'window\.location\s*=\s*["\']([^"\']+)',
        r'location\.href\s*=\s*["\']([^"\']+)',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            url = match.group(1).strip()
            if url and not url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                full_url = urljoin(base_url, url)
                links.add(full_url)
    return links


def extract_forms(html, base_url):
    """Extract all forms with their inputs."""
    forms = []
    form_blocks = re.findall(r"<form\b[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE)

    for i, block in enumerate(re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.DOTALL | re.IGNORECASE)):
        attrs = block.group(1)
        body = block.group(2)

        action_match = re.search(r'action=["\']([^"\']*)', attrs)
        method_match = re.search(r'method=["\']([^"\']*)', attrs, re.IGNORECASE)

        action = urljoin(base_url, action_match.group(1)) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "GET"

        inputs = []
        for inp in re.finditer(r"<input\b([^>]*)>", body, re.IGNORECASE):
            inp_attrs = inp.group(1)
            name = re.search(r'name=["\']([^"\']*)', inp_attrs)
            type_ = re.search(r'type=["\']([^"\']*)', inp_attrs, re.IGNORECASE)
            value = re.search(r'value=["\']([^"\']*)', inp_attrs)
            if name:
                inputs.append({
                    "name": name.group(1),
                    "type": type_.group(1).lower() if type_ else "text",
                    "value": value.group(1) if value else "",
                })

        # Also grab textareas and selects
        for ta in re.finditer(r'<textarea\b[^>]*name=["\']([^"\']*)', body, re.IGNORECASE):
            inputs.append({"name": ta.group(1), "type": "textarea", "value": ""})
        for sel in re.finditer(r'<select\b[^>]*name=["\']([^"\']*)', body, re.IGNORECASE):
            inputs.append({"name": sel.group(1), "type": "select", "value": ""})

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def extract_comments(html):
    """Extract HTML comments — often contain juicy info."""
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    interesting = []
    keywords = ["todo", "fixme", "hack", "bug", "password", "secret", "key",
                "token", "admin", "debug", "test", "temp", "deprecated",
                "remove", "internal", "api", "endpoint", "credentials"]
    for comment in comments:
        comment_clean = comment.strip()
        if any(kw in comment_clean.lower() for kw in keywords):
            interesting.append(comment_clean[:500])
    return interesting


def crawl(start_url, scope=None, max_pages=100, max_depth=5, verbose=True):
    """
    Crawl a website starting from start_url.
    Returns dict with pages, forms, params, comments, and all discovered URLs.
    """
    client = HTTPClient(rate_limit=0.3, timeout=10, retries=1)

    if scope is None:
        scope = ScopeChecker()
        parsed = urlparse(start_url)
        scope.add_target(parsed.hostname)

    visited = set()
    queue = deque([(start_url, 0)])  # (url, depth)
    all_urls = set()
    all_forms = []
    all_params = set()
    all_comments = []
    pages = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()

        # Normalize URL
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if normalized in visited:
            continue
        if not scope.is_in_scope(url):
            continue

        # Skip non-HTML resources
        skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js",
                    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
                    ".pdf", ".zip", ".tar", ".gz", ".rar")
        if parsed.path.lower().endswith(skip_ext):
            all_urls.add(url)
            continue

        visited.add(normalized)

        if verbose:
            print(f"  [{len(visited)}/{max_pages}] {url[:80]}", flush=True)

        resp = client.get(url)
        if not resp or resp.status_code >= 400:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            continue

        pages.append({
            "url": url,
            "status": resp.status_code,
            "title": re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.IGNORECASE | re.DOTALL),
        })
        # Fix title
        pages[-1]["title"] = pages[-1]["title"].group(1).strip()[:100] if pages[-1]["title"] else ""

        # Extract query params
        if parsed.query:
            for param in parse_qs(parsed.query):
                all_params.add(f"{parsed.path}?{param}")

        # Extract links
        links = extract_links(resp.text, url)
        all_urls.update(links)

        # Extract forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            form["found_on"] = url
            all_forms.append(form)
            for inp in form["inputs"]:
                all_params.add(f"{form['action']}:{inp['name']}")

        # Extract comments
        comments = extract_comments(resp.text)
        for c in comments:
            all_comments.append({"page": url, "comment": c})

        # Add new links to queue
        if depth < max_depth:
            for link in links:
                link_parsed = urlparse(link)
                link_norm = f"{link_parsed.scheme}://{link_parsed.netloc}{link_parsed.path}"
                if link_norm not in visited and scope.is_in_scope(link):
                    queue.append((link, depth + 1))

    results = {
        "pages": pages,
        "urls": sorted(all_urls),
        "forms": all_forms,
        "params": sorted(all_params),
        "comments": all_comments,
        "stats": {
            "pages_crawled": len(visited),
            "urls_found": len(all_urls),
            "forms_found": len(all_forms),
            "params_found": len(all_params),
            "comments_found": len(all_comments),
        },
    }

    if verbose:
        print(f"\n  Pages crawled: {results['stats']['pages_crawled']}")
        print(f"  URLs found: {results['stats']['urls_found']}")
        print(f"  Forms found: {results['stats']['forms_found']}")
        print(f"  Parameters: {results['stats']['params_found']}")
        print(f"  Interesting comments: {results['stats']['comments_found']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python spider.py <url> [max_pages]")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    max_p = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    print(f"\n[*] Crawling: {url} (max {max_p} pages)\n")
    crawl(url, max_pages=max_p)
