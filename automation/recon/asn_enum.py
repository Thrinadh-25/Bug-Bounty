"""ASN / netblock enumeration for a target domain or IP.

Tries, in order:
    - `whois` CLI
    - BGPView API (https://bgpview.io/)
    - ipinfo.io (if token in API_KEYS)
"""

import json
import socket

from ..exploits._common import have, run_cmd, make_client


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _bgpview_ip(client, ip):
    r = client.get(f"https://api.bgpview.io/ip/{ip}")
    if not r or r.status_code != 200:
        return None
    try:
        return r.json().get("data", {})
    except Exception:
        return None


def _bgpview_asn_prefixes(client, asn_num):
    r = client.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes")
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json().get("data", {})
        return [p.get("prefix") for p in data.get("ipv4_prefixes", []) if p.get("prefix")]
    except Exception:
        return []


def run(target, api_keys=None, client=None, timeout=20):
    """Return {asn, org, country, prefixes:[...], sources:[...]}."""
    client = make_client(client)
    api_keys = api_keys or {}
    host = target
    if isinstance(target, dict):
        host = target.get("host") or target.get("domain") or target.get("url")
    if not host:
        return {}
    # strip scheme if URL
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    ip = host if host.replace(".", "").isdigit() else _resolve(host)
    out = {"host": host, "ip": ip, "asn": None, "org": None, "country": None, "prefixes": [], "sources": []}
    if not ip:
        return out

    data = _bgpview_ip(client, ip)
    if data:
        prefixes = data.get("prefixes") or []
        if prefixes:
            asn_obj = prefixes[0].get("asn", {}) or {}
            out["asn"] = asn_obj.get("asn")
            out["org"] = asn_obj.get("description") or asn_obj.get("name")
            out["country"] = asn_obj.get("country_code") or data.get("rir_allocation", {}).get("country_code")
        out["sources"].append("bgpview")
        if out["asn"]:
            out["prefixes"] = _bgpview_asn_prefixes(client, out["asn"])

    if not out["asn"] and have("whois"):
        rc, stdout, _ = run_cmd(["whois", ip], timeout=timeout)
        if rc == 0:
            for ln in stdout.splitlines():
                if ln.lower().startswith(("origin:", "originas:")):
                    out["asn"] = ln.split(":", 1)[1].strip().lstrip("AS")
                elif ln.lower().startswith("orgname:") or ln.lower().startswith("org-name:"):
                    out["org"] = ln.split(":", 1)[1].strip()
                elif ln.lower().startswith("country:"):
                    out["country"] = ln.split(":", 1)[1].strip()
            out["sources"].append("whois")

    token = api_keys.get("ipinfo") or api_keys.get("IPINFO_TOKEN")
    if token and not out["asn"]:
        r = client.get(f"https://ipinfo.io/{ip}/json", params={"token": token})
        if r and r.status_code == 200:
            try:
                j = r.json()
                out["org"] = out["org"] or j.get("org")
                out["country"] = out["country"] or j.get("country")
                out["sources"].append("ipinfo")
            except Exception:
                pass
    return out
