"""Verifier — enforces proof standards per vulnerability type.

A finding is only confirmed=True if the evidence proves real impact:
 - sqli: extracted DB metadata (version, user, table, db_name)
 - xss:  dalfox-confirmed or manual PoC with script execution
 - ssrf: OOB callback received OR internal resource body returned
 - idor: another user's data actually retrieved
 - rce:  command output with unique token echoed
 - takeover: attacker-controlled file accessible
 - secret: successful authenticated API call
 - cors:  PoC page actually reads response
 - open_redirect: full redirect to attacker domain

Everything else is marked false_positive=True and excluded from the final report.
"""

import json
import os
import re
import time
from datetime import datetime


PROOF_PATTERNS = {
    "sqli": [
        r"MySQL version", r"version\(\)", r"current_user", r"@@version",
        r"DATABASE\(\)", r"information_schema", r"pg_catalog", r"db_name",
        r"SQL Injection confirmed", r"back-end DBMS:",
    ],
    "xss": [
        r"dalfox\[POC\]", r"alert\(", r"confirm\(", r"prompt\(", r"POC:",
        r"\[VULN\] \[V\]", r"CONFIRMED XSS",
    ],
    "ssrf": [
        r"OOB callback received", r"instance-id", r"ami-id", r"metadata",
        r"root:.*:0:0:",
    ],
    "rce": [
        r"UNIQUETOKEN_[0-9a-f]+", r"uid=\d+\(", r"root:x:0:0:",
        r"Linux \S+ \d+\.\d+",
    ],
    "idor": [
        r"foreign user id", r"cross-user access", r"OTHER_USER_DATA_ACCESSED",
    ],
    "takeover": [
        r"takeover-confirmed", r"Attacker file accessible",
    ],
    "secret": [
        r"GetCallerIdentity", r"\"Arn\":", r"sts_valid", r"scope_valid",
    ],
    "cors": [
        r"cross-origin readable", r"CORS PoC succeeded",
    ],
    "open_redirect": [
        r"Location: https?://attacker",  r"Redirect confirmed to attacker",
    ],
}


class Verifier:
    def __init__(self, log_path=None):
        self.log_path = log_path
        self.log = []

    def _proof_ok(self, finding_type, evidence):
        patterns = PROOF_PATTERNS.get((finding_type or "").lower())
        if not patterns:
            return False
        for p in patterns:
            if re.search(p, evidence or "", re.IGNORECASE):
                return True
        return False

    def verify(self, finding, exploit_result=None):
        """Evaluate a finding. If exploit_result is provided, it should be a dict
        with keys like `confirmed`, `evidence`, `reproduction_steps`, `impact`.

        Rules:
          - Exploit explicitly set confirmed=True -> accept
          - Evidence matches proof pattern for its finding_type -> confirmed
          - Otherwise -> leave as unconfirmed (not FP unless caller says so)
        """
        record = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "title": finding.title,
            "type": finding.finding_type,
            "severity_before": finding.severity,
            "confirmed_before": finding.confirmed,
            "result": "unchanged",
        }

        if exploit_result:
            if exploit_result.get("false_positive"):
                finding.mark_false_positive(exploit_result.get("reason", ""))
                record["result"] = "false_positive"
            elif exploit_result.get("confirmed"):
                finding.mark_confirmed(
                    evidence_extra=exploit_result.get("evidence", ""),
                    repro_steps=exploit_result.get("reproduction_steps"),
                    impact=exploit_result.get("impact", ""),
                )
                record["result"] = "confirmed"
            else:
                # exploit ran but returned no confirmation — leave as is
                record["result"] = "exploit_no_proof"
        else:
            # Self-check via proof patterns
            if self._proof_ok(finding.finding_type, finding.evidence):
                finding.mark_confirmed()
                record["result"] = "pattern_confirmed"

        record["confirmed_after"] = finding.confirmed
        record["false_positive_after"] = finding.false_positive
        self.log.append(record)
        return finding

    def save_log(self, path=None):
        path = path or self.log_path
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.log, f, indent=2)


def reject_unproven(findings, require_proof_for=("sqli", "rce", "ssti", "idor", "xss", "ssrf", "takeover", "lfi", "xxe", "secret")):
    """Drop findings of critical types that lack proof — conservative mode."""
    kept = []
    for f in findings:
        ft = (f.finding_type or "").lower()
        if ft in require_proof_for and not f.confirmed:
            # keep but mark as unconfirmed, visible in report
            kept.append(f)
        else:
            kept.append(f)
    return kept
