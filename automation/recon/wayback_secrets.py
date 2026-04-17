"""Pull historical URLs from the Wayback Machine and grep for secrets.

Uses web.archive.org's CDX API (no key required).
"""

import re

from ..exploits._common import make_client


SECRET_REGEX = [
    ("aws_access_key_id", re.compile(r"A(KIA|SIA)[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("stripe_live", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("stripe_restricted", re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("github_pat", re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")),
    ("private_key", re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----")),
]

INTERESTING_EXTENSIONS = (".js", ".json", ".env", ".config", ".bak", ".txt", ".yml", ".yaml", ".log", ".conf")


def _cdx_urls(client, host, limit, timeout):
    r = client.get(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"{host}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(limit),
        },
        timeout=timeout,
    )
    if not r or r.status_code != 200:
        return []
    try:
        rows = r.json()
        return [row[0] for row in rows[1:]]  # first row is header
    except Exception:
        return []


def run(target, api_keys=None, client=None, timeout=30, max_urls=250, max_fetch=40):
    host = target
    if isinstance(target, dict):
        host = target.get("host") or target.get("domain") or target.get("url") or ""
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    if not host:
        return {"urls": [], "secrets": []}
    client = make_client(client)
    urls = _cdx_urls(client, host, max_urls, timeout)
    # focus on interesting extensions first
    fetch = [u for u in urls if u.lower().endswith(INTERESTING_EXTENSIONS)][:max_fetch]
    secrets = []
    for u in fetch:
        r = client.get(u, timeout=timeout, allow_redirects=True)
        if not r or not r.text:
            continue
        txt = r.text
        for label, rx in SECRET_REGEX:
            for m in rx.finditer(txt):
                secrets.append({"type": label, "url": u, "match": m.group(0)[:80]})
    # dedup
    seen = set()
    uniq = []
    for s in secrets:
        k = (s["type"], s["match"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return {"urls": urls, "inspected": fetch, "secrets": uniq}
