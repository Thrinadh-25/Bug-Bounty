"""Censys search for hosts / certificates matching the target.

Requires api_keys["censys_id"] and api_keys["censys_secret"] (v2 API).
"""

import base64
import socket

from ..exploits._common import make_client


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def run(target, api_keys=None, client=None, timeout=20):
    api_keys = api_keys or {}
    cid = api_keys.get("censys_id") or api_keys.get("CENSYS_API_ID")
    csec = api_keys.get("censys_secret") or api_keys.get("CENSYS_API_SECRET")
    if not cid or not csec:
        return {"note": "no censys credentials"}
    host = target
    if isinstance(target, dict):
        host = target.get("host") or target.get("domain") or target.get("url") or ""
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    if not host:
        return {}
    auth = "Basic " + base64.b64encode(f"{cid}:{csec}".encode()).decode()
    client = make_client(client)
    out = {"host": host, "hosts": [], "certs": []}

    # host search by name or IP
    ip = host if host.replace(".", "").isdigit() else _resolve(host)
    if ip:
        r = client.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                       headers={"Authorization": auth})
        if r and r.status_code == 200:
            try:
                h = r.json().get("result", {}) or {}
                out["hosts"].append({
                    "ip": h.get("ip"),
                    "services": [{"port": s.get("port"), "service_name": s.get("service_name")}
                                 for s in h.get("services", [])],
                    "location": h.get("location", {}).get("country"),
                })
            except Exception:
                pass
    # certificate search
    root = ".".join(host.split(".")[-2:])
    r = client.get("https://search.censys.io/api/v2/certificates/search",
                   params={"q": f"names: {root}", "per_page": 20},
                   headers={"Authorization": auth})
    if r and r.status_code == 200:
        try:
            hits = r.json().get("result", {}).get("hits", [])
            for c in hits:
                out["certs"].append({
                    "subject": c.get("parsed", {}).get("subject_dn"),
                    "names": c.get("names", [])[:20],
                    "fingerprint": c.get("fingerprint_sha256"),
                })
        except Exception:
            pass
    return out
