"""
JavaScript file analysis — extract secrets, endpoints, and interesting data from JS files.
This is a gold mine in bug bounties.
"""

import re
import sys
import os
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient

# Patterns to hunt for in JS files
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase URL": r"https?://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key": r"(?i)firebase.*?['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
    "Slack Token": r"xox[bpors]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{24}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Stripe Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "PayPal Braintree Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Hardcoded Password": r"""(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{4,}['\"]""",
    "Authorization Header": r"""(?i)['\"]authorization['\"]:\s*['\"](?:Bearer|Basic|Token)\s+[^'\"]+['\"]""",
    "S3 Bucket": r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.-]+",
    "Internal IP": r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
}

ENDPOINT_PATTERNS = [
    r"""(?:"|')(/api/[a-zA-Z0-9_/\-{}?&=.]+)(?:"|')""",
    r"""(?:"|')(/v[0-9]+/[a-zA-Z0-9_/\-{}?&=.]+)(?:"|')""",
    r"""(?:"|')(https?://[a-zA-Z0-9._\-/]+)(?:"|')""",
    r"""(?:"|')(/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+)(?:"|')""",
    r"""fetch\(\s*[`'"](.*?)[`'"]\s*""",
    r"""axios\.\w+\(\s*[`'"](.*?)[`'"]\s*""",
    r"""\.ajax\(\s*\{[^}]*url\s*:\s*[`'"](.*?)[`'"]""",
    r"""XMLHttpRequest.*?\.open\(\s*['"]\w+['"]\s*,\s*['"](.*?)['"]""",
]

EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"


def extract_js_urls(html, base_url):
    """Extract all JS file URLs from HTML."""
    js_urls = set()
    patterns = [
        r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
        r"""(?:"|')(https?://[^"']+\.js(?:\?[^"']*)?)["\']""",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url.startswith("//"):
                url = "https:" + url
            elif not url.startswith("http"):
                url = urljoin(base_url, url)
            js_urls.add(url)
    return js_urls


def analyze_js(content, source_url=""):
    """Analyze a JS file's content for secrets and endpoints."""
    findings = {"secrets": [], "endpoints": set(), "emails": set()}

    # Hunt secrets
    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, content):
            findings["secrets"].append({
                "type": name,
                "value": match.group(0)[:200],
                "source": source_url,
            })

    # Hunt endpoints
    for pattern in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content):
            endpoint = match.group(1)
            if endpoint and len(endpoint) > 1 and not endpoint.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".woff")):
                findings["endpoints"].add(endpoint)

    # Hunt emails
    for match in re.finditer(EMAIL_PATTERN, content):
        email = match.group(0)
        if not email.endswith((".png", ".jpg", ".js", ".css")):
            findings["emails"].add(email)

    findings["endpoints"] = sorted(findings["endpoints"])
    findings["emails"] = sorted(findings["emails"])
    return findings


def recon(url, client=None, verbose=True):
    """Full JS recon for a target URL — discover JS files and analyze them all."""
    client = client or HTTPClient(timeout=15)

    if verbose:
        print(f"  Fetching {url}...", flush=True)

    resp = client.get(url)
    if not resp:
        return {"js_files": [], "secrets": [], "endpoints": [], "emails": []}

    js_urls = extract_js_urls(resp.text, url)

    # Also analyze inline scripts
    inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", resp.text, re.DOTALL | re.IGNORECASE)
    inline_content = "\n".join(inline_scripts)

    all_secrets = []
    all_endpoints = set()
    all_emails = set()

    # Analyze inline JS
    if inline_content.strip():
        findings = analyze_js(inline_content, f"{url} (inline)")
        all_secrets.extend(findings["secrets"])
        all_endpoints.update(findings["endpoints"])
        all_emails.update(findings["emails"])

    # Analyze external JS files
    if verbose:
        print(f"  Found {len(js_urls)} JS files to analyze")

    for js_url in js_urls:
        if verbose:
            print(f"    -> {js_url[:80]}...", flush=True)
        js_resp = client.get(js_url)
        if js_resp and js_resp.status_code == 200:
            findings = analyze_js(js_resp.text, js_url)
            all_secrets.extend(findings["secrets"])
            all_endpoints.update(findings["endpoints"])
            all_emails.update(findings["emails"])

    return {
        "js_files": sorted(js_urls),
        "secrets": all_secrets,
        "endpoints": sorted(all_endpoints),
        "emails": sorted(all_emails),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python js_recon.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] JS Recon: {url}\n")
    results = recon(url)
    print(f"\n[+] JS files: {len(results['js_files'])}")
    print(f"[+] Secrets: {len(results['secrets'])}")
    print(f"[+] Endpoints: {len(results['endpoints'])}")
    print(f"[+] Emails: {len(results['emails'])}")
    if results["secrets"]:
        print("\n=== SECRETS ===")
        for s in results["secrets"]:
            print(f"  [{s['type']}] {s['value'][:80]}")
    if results["endpoints"][:20]:
        print("\n=== ENDPOINTS (top 20) ===")
        for e in results["endpoints"][:20]:
            print(f"  {e}")
