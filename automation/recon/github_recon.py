"""GitHub code search for leaked secrets / references to a target domain.

Requires api_keys["github"] (classic PAT or fine-grained, read-only is enough).
"""

import re
import time

from ..exploits._common import make_client


SECRET_HINTS = [
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "aws_secret_access_key", "AKIA", "BEGIN PRIVATE KEY",
    "AIza", "ghp_", "xox", "sk_live_",
]


def _search_code(client, token, query, timeout):
    r = client.get(
        "https://api.github.com/search/code",
        params={"q": query, "per_page": 20},
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"token {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=timeout,
    )
    if not r or r.status_code != 200:
        return []
    try:
        return r.json().get("items", [])
    except Exception:
        return []


def run(target, api_keys=None, client=None, timeout=20):
    api_keys = api_keys or {}
    token = api_keys.get("github") or api_keys.get("GITHUB_TOKEN")
    if not token:
        return {"hits": [], "note": "no github token supplied"}
    host = target
    if isinstance(target, dict):
        host = target.get("host") or target.get("domain") or target.get("url") or ""
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    if not host:
        return {"hits": []}
    root = ".".join(host.split(".")[-2:])
    client = make_client(client)
    hits = []
    for kw in SECRET_HINTS:
        items = _search_code(client, token, f'"{root}" {kw}', timeout)
        for it in items:
            hits.append({
                "repo": it.get("repository", {}).get("full_name"),
                "path": it.get("path"),
                "url": it.get("html_url"),
                "keyword": kw,
            })
        time.sleep(1.0)  # respect secondary rate limits
    # De-dup
    seen = set()
    uniq = []
    for h in hits:
        k = (h.get("repo"), h.get("path"))
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return {"hits": uniq}
