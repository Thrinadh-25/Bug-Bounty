"""Cloud-asset candidate generator (S3 / GCS / Azure blob) from target names.

This is pure candidate generation — validation lives in
`exploits/s3_enum.py`, `exploits/gcs_enum.py`, `exploits/azure_blob_enum.py`.
"""

from ..exploits._common import make_client


SUFFIXES = [
    "", "-prod", "-staging", "-stg", "-dev", "-qa", "-test", "-assets",
    "-backup", "-backups", "-uploads", "-media", "-static", "-logs",
    "-internal", "-private", "-public", "-cdn",
]


def _roots(target):
    host = target
    if isinstance(target, dict):
        host = target.get("host") or target.get("domain") or target.get("url") or ""
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    if not host:
        return []
    parts = host.split(".")
    stems = {host, parts[0]}
    if len(parts) >= 2:
        stems.add(".".join(parts[-2:]))
        stems.add(parts[-2])
    out = []
    for s in stems:
        s = s.lower()
        for v in (s, s.replace(".", "-"), s.replace(".", "")):
            if v and v not in out:
                out.append(v)
    return out


def run(target, api_keys=None, client=None, timeout=10):
    client = make_client(client)
    stems = _roots(target)
    s3, gcs, azure = [], [], []
    for r in stems:
        for s in SUFFIXES:
            name = (r + s).strip("-").lower()
            if 3 <= len(name) <= 63 and name not in s3:
                s3.append(name)
            if 3 <= len(name) <= 63 and name not in gcs:
                gcs.append(name)
            az = "".join(c for c in name if c.isalnum())
            if 3 <= len(az) <= 24 and az not in azure:
                azure.append(az)
    return {"s3": s3, "gcs": gcs, "azure": azure}
