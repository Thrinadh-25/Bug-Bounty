"""Shodan host + search lookups for a target domain / IP.

Requires api_keys["shodan"].
"""

import socket

from ..exploits._common import make_client


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def run(target, api_keys=None, client=None, timeout=20):
    api_keys = api_keys or {}
    key = api_keys.get("shodan") or api_keys.get("SHODAN_API_KEY")
    if not key:
        return {"note": "no shodan key"}
    host = target
    if isinstance(target, dict):
        host = target.get("host") or target.get("domain") or target.get("url") or ""
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    if not host:
        return {}
    ip = host if host.replace(".", "").isdigit() else _resolve(host)
    client = make_client(client)
    out = {"host": host, "ip": ip, "services": [], "domains": [], "hostnames": []}
    if ip:
        r = client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key})
        if r and r.status_code == 200:
            try:
                j = r.json()
                out["hostnames"] = j.get("hostnames", [])
                out["domains"] = j.get("domains", [])
                for svc in j.get("data", []):
                    out["services"].append({
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "banner": (svc.get("data") or "")[:200],
                    })
            except Exception:
                pass
    # domain search
    root = ".".join(host.split(".")[-2:])
    r = client.get("https://api.shodan.io/dns/domain/" + root, params={"key": key})
    if r and r.status_code == 200:
        try:
            j = r.json()
            subs = {x.get("subdomain") for x in j.get("data", []) if x.get("subdomain")}
            out["subdomains"] = sorted(s for s in subs if s)
        except Exception:
            pass
    return out
