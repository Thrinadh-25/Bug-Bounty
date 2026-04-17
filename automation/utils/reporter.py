"""
Report generator — turns scan results into markdown, executive md, HackerOne/Bugcrowd JSON, and styled HTML.

Finding is backward-compatible: old code `Finding(title, severity, description, url, evidence, remediation)`
still works. New kwargs: confirmed, false_positive, cvss, impact, reproduction_steps, references,
context, finding_type, params, payload.
"""

import html
import json
import os
from datetime import datetime


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#8b0000",
    "high": "#d94c4c",
    "medium": "#f0ad4e",
    "low": "#5bc0de",
    "info": "#888888",
}

# Base CVSS-ish score per vuln type (pre-verification)
_BASE_CVSS = {
    "sqli": 9.8,
    "rce": 9.8,
    "ssti": 9.8,
    "xxe": 8.5,
    "lfi": 7.5,
    "ssrf": 8.1,
    "idor": 6.5,
    "xss": 6.1,
    "xss_stored": 8.0,
    "open_redirect": 4.3,
    "cors": 5.4,
    "crlf": 5.0,
    "takeover": 9.1,
    "csrf": 6.5,
    "secret": 8.1,
    "s3_public_write": 9.1,
    "jwt_forgery": 9.8,
    "smuggling": 9.0,
    "oauth": 7.5,
    "prototype_pollution": 7.0,
    "race_condition": 6.5,
    "information_disclosure": 5.3,
    "weak_tls": 5.3,
    "header": 3.1,
    "dns": 3.7,
    "method_tamper": 4.3,
    "rate_limit": 4.3,
    "dns_zone_transfer": 7.5,
    "default": 5.0,
}


def _clamp(v, lo=0.0, hi=10.0):
    return max(lo, min(hi, v))


def score_cvss(finding_type: str, auth_required=False, user_interaction=False, scope_change=False):
    base = _BASE_CVSS.get((finding_type or "").lower(), _BASE_CVSS["default"])
    if auth_required:
        base -= 1.0
    if user_interaction:
        base -= 0.8
    if scope_change:
        base += 0.8
    return round(_clamp(base), 1)


def severity_from_cvss(cvss):
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss >= 0.1:
        return "low"
    return "info"


class Finding:
    """A single security finding.

    Legacy positional args: title, severity, description, url, evidence, remediation
    New kwargs:
        confirmed (bool)           — True only if verified with actual impact proof
        false_positive (bool)      — explicitly flagged as FP by verifier
        cvss (float)               — CVSS 0-10
        impact (str)               — what an attacker can actually do
        reproduction_steps (list)  — numbered reproduction commands/steps
        references (list)          — CVE/OWASP/writeup URLs
        context (dict)             — free-form structured context for trigger engine
        finding_type (str)         — canonical key (sqli, xss, ssrf, ...) used by trigger engine
        params (dict)              — parameters involved
        payload (str)              — payload that triggered
    """

    __slots__ = (
        "title", "severity", "description", "url", "evidence", "remediation",
        "confirmed", "false_positive", "cvss", "impact",
        "reproduction_steps", "references", "context",
        "finding_type", "params", "payload", "discovered_at",
    )

    def __init__(
        self,
        title,
        severity,
        description,
        url="",
        evidence="",
        remediation="",
        confirmed=False,
        false_positive=False,
        cvss=None,
        impact="",
        reproduction_steps=None,
        references=None,
        context=None,
        finding_type=None,
        params=None,
        payload="",
    ):
        self.title = title
        self.severity = (severity or "info").lower()
        self.description = description
        self.url = url
        self.evidence = evidence
        self.remediation = remediation
        self.confirmed = bool(confirmed)
        self.false_positive = bool(false_positive)
        self.impact = impact
        self.reproduction_steps = list(reproduction_steps or [])
        self.references = list(references or [])
        self.context = dict(context or {})
        self.finding_type = finding_type
        self.params = dict(params or {})
        self.payload = payload
        self.discovered_at = datetime.utcnow().isoformat() + "Z"

        if cvss is None:
            self.cvss = score_cvss(finding_type or self.severity)
        else:
            self.cvss = float(cvss)

    def mark_confirmed(self, evidence_extra="", repro_steps=None, impact=""):
        self.confirmed = True
        self.false_positive = False
        if evidence_extra:
            self.evidence = (self.evidence + "\n\n[VERIFIED]\n" + evidence_extra).strip()
        if repro_steps:
            self.reproduction_steps = list(repro_steps)
        if impact:
            self.impact = impact

    def mark_false_positive(self, reason=""):
        self.confirmed = False
        self.false_positive = True
        if reason:
            self.evidence = (self.evidence + f"\n\n[FP] {reason}").strip()

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss": self.cvss,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
            "finding_type": self.finding_type,
            "description": self.description,
            "url": self.url,
            "params": self.params,
            "payload": self.payload,
            "evidence": self.evidence,
            "impact": self.impact,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "references": self.references,
            "context": self.context,
            "discovered_at": self.discovered_at,
        }

    @classmethod
    def from_dict(cls, d):
        f = cls(
            title=d.get("title", ""),
            severity=d.get("severity", "info"),
            description=d.get("description", ""),
            url=d.get("url", ""),
            evidence=d.get("evidence", ""),
            remediation=d.get("remediation", ""),
            confirmed=d.get("confirmed", False),
            false_positive=d.get("false_positive", False),
            cvss=d.get("cvss"),
            impact=d.get("impact", ""),
            reproduction_steps=d.get("reproduction_steps"),
            references=d.get("references"),
            context=d.get("context"),
            finding_type=d.get("finding_type"),
            params=d.get("params"),
            payload=d.get("payload", ""),
        )
        if d.get("discovered_at"):
            f.discovered_at = d["discovered_at"]
        return f


class Reporter:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = output_dir
        self.findings = []
        self.recon_data = {}
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "recon"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "findings"), exist_ok=True)

    def add_finding(self, finding):
        if finding is not None:
            self.findings.append(finding)

    def add_findings(self, findings):
        for f in (findings or []):
            if f is not None:
                self.findings.append(f)

    def save_recon(self, name, data):
        self.recon_data[name] = data
        path = os.path.join(self.output_dir, "recon", name)
        if isinstance(data, list):
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(str(item) for item in data))
        elif isinstance(data, dict):
            json_path = path if path.endswith(".json") else path.rsplit(".", 1)[0] + ".json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(str(data))

    def save_findings(self, scanner_name, findings):
        path = os.path.join(self.output_dir, "findings", f"{scanner_name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([fi.to_dict() for fi in (findings or [])], f, indent=2)

    def _reportable(self):
        """Findings that should appear in the final report: not FP, sorted by severity."""
        out = [f for f in self.findings if not f.false_positive]
        return sorted(out, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.cvss))

    def _severity_counts(self, findings):
        c = {}
        for f in findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    # -------- Output Formats --------
    def _write_markdown(self, findings, counts):
        lines = []
        lines.append(f"# Bug Bounty Report: {self.target}")
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")
        lines.append("## Summary")
        lines.append(f"**Total findings:** {len(findings)}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"- **{sev.upper()}:** {counts[sev]}")
        confirmed = sum(1 for f in findings if f.confirmed)
        lines.append(f"- **CONFIRMED (verified exploitable):** {confirmed}")
        lines.append("")

        if self.recon_data:
            lines.append("## Recon Results")
            for name, data in self.recon_data.items():
                if isinstance(data, list):
                    lines.append(f"- **{name}:** {len(data)} items")
                else:
                    lines.append(f"- **{name}:** saved")
            lines.append("")

        if findings:
            lines.append("## Findings")
            for i, f in enumerate(findings, 1):
                tag = "[CONFIRMED]" if f.confirmed else "[UNCONFIRMED]"
                lines.append(f"### {i}. [{f.severity.upper()}] {tag} {f.title}")
                lines.append(f"- **CVSS:** {f.cvss}")
                if f.url:
                    lines.append(f"- **URL:** `{f.url}`")
                if f.finding_type:
                    lines.append(f"- **Type:** `{f.finding_type}`")
                if f.params:
                    lines.append(f"- **Parameters:** `{', '.join(f.params.keys())}`")
                if f.payload:
                    lines.append(f"- **Payload:** `{f.payload[:300]}`")
                lines.append("")
                lines.append(f.description)
                if f.impact:
                    lines.append(f"\n**Impact:** {f.impact}")
                if f.evidence:
                    lines.append(f"\n**Evidence:**\n```\n{f.evidence}\n```")
                if f.reproduction_steps:
                    lines.append("\n**Reproduction Steps:**")
                    for j, step in enumerate(f.reproduction_steps, 1):
                        lines.append(f"{j}. {step}")
                if f.remediation:
                    lines.append(f"\n**Remediation:** {f.remediation}")
                if f.references:
                    lines.append("\n**References:**")
                    for ref in f.references:
                        lines.append(f"- {ref}")
                lines.append("")
        else:
            lines.append("## Findings\nNo vulnerabilities found.")

        path = os.path.join(self.output_dir, "report.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def _write_executive(self, findings, counts):
        lines = []
        lines.append(f"# Executive Summary — {self.target}")
        lines.append(f"_Generated {datetime.now().strftime('%Y-%m-%d')}_\n")
        lines.append("## Risk Overview")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"- **{sev.upper()}:** {counts[sev]}")
        confirmed = [f for f in findings if f.confirmed]
        lines.append(f"\n**Verified exploitable:** {len(confirmed)} of {len(findings)} findings")
        lines.append("")
        if confirmed:
            lines.append("## Top Confirmed Issues")
            for f in confirmed[:10]:
                lines.append(f"- **[{f.severity.upper()}] {f.title}** — {f.impact or f.description[:160]}")
        lines.append("\n## Recommended Actions")
        lines.append("1. Remediate all CRITICAL/HIGH confirmed findings immediately.")
        lines.append("2. Audit code/config for similar instances of the same vulnerability pattern.")
        lines.append("3. Deploy monitoring/WAF rules for the attack patterns observed.")
        path = os.path.join(self.output_dir, "report_executive.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def _write_hackerone_json(self, findings):
        payload = []
        for f in findings:
            payload.append({
                "title": f.title,
                "vulnerability_information": (
                    f"{f.description}\n\n"
                    f"Impact: {f.impact}\n\n"
                    f"Steps to reproduce:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(f.reproduction_steps, 1))
                    + f"\n\nEvidence:\n{f.evidence}"
                ),
                "severity_rating": f.severity,
                "weakness_id": f.finding_type or "other",
                "structured_scope": {"asset_identifier": f.url or self.target},
                "cvss_vector": f.cvss,
                "references": f.references,
                "confirmed": f.confirmed,
            })
        path = os.path.join(self.output_dir, "report_hackerone.json")
        with open(path, "w", encoding="utf-8") as fp:
            json.dump({"target": self.target, "findings": payload}, fp, indent=2)
        return path

    def _write_bugcrowd_json(self, findings):
        payload = []
        sev_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P5"}
        for f in findings:
            payload.append({
                "title": f.title,
                "priority": sev_map.get(f.severity, "P5"),
                "description": f.description,
                "impact": f.impact,
                "steps_to_reproduce": f.reproduction_steps,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "target": f.url or self.target,
                "bug_type": f.finding_type or "other",
                "cvss_score": f.cvss,
                "verified": f.confirmed,
                "references": f.references,
            })
        path = os.path.join(self.output_dir, "report_bugcrowd.json")
        with open(path, "w", encoding="utf-8") as fp:
            json.dump({"target": self.target, "findings": payload}, fp, indent=2)
        return path

    def _write_html(self, findings, counts):
        rows = []
        for i, f in enumerate(findings, 1):
            color = SEVERITY_COLOR.get(f.severity, "#888")
            conf = "✔" if f.confirmed else "·"
            rows.append(
                f"<tr data-sev='{f.severity}'>"
                f"<td>{i}</td>"
                f"<td style='color:{color};font-weight:bold'>{f.severity.upper()}</td>"
                f"<td>{f.cvss}</td>"
                f"<td>{conf}</td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td><code>{html.escape(f.url)}</code></td>"
                f"<td>{html.escape(f.finding_type or '')}</td>"
                f"</tr>"
            )
        details = []
        for i, f in enumerate(findings, 1):
            color = SEVERITY_COLOR.get(f.severity, "#888")
            steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in f.reproduction_steps)
            refs_html = "".join(f"<li><a href='{html.escape(r)}'>{html.escape(r)}</a></li>" for r in f.references)
            details.append(f"""
<section id='f{i}'>
  <h3 style='border-left:6px solid {color};padding-left:10px'>
    #{i}. [{f.severity.upper()}] {html.escape(f.title)}
    <small style='color:#666'>CVSS {f.cvss} &middot; {'CONFIRMED' if f.confirmed else 'unconfirmed'}</small>
  </h3>
  <p><b>URL:</b> <code>{html.escape(f.url)}</code></p>
  <p>{html.escape(f.description)}</p>
  {f'<p><b>Impact:</b> {html.escape(f.impact)}</p>' if f.impact else ''}
  <pre>{html.escape(f.evidence)}</pre>
  {f'<b>Repro steps:</b><ol>{steps_html}</ol>' if steps_html else ''}
  <p><b>Remediation:</b> {html.escape(f.remediation)}</p>
  {f'<b>References:</b><ul>{refs_html}</ul>' if refs_html else ''}
</section>
""")
        counts_html = "".join(
            f"<span class='chip chip-{s}'>{s.upper()}: {counts.get(s, 0)}</span>"
            for s in ["critical", "high", "medium", "low", "info"]
        )
        doc = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Bug Bounty Report — {html.escape(self.target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#222}}
 h1{{border-bottom:2px solid #222;padding-bottom:6px}}
 .chip{{display:inline-block;padding:4px 10px;margin:2px;border-radius:12px;color:#fff;font-size:12px;font-weight:bold}}
 .chip-critical{{background:#8b0000}} .chip-high{{background:#d94c4c}}
 .chip-medium{{background:#f0ad4e}} .chip-low{{background:#5bc0de}} .chip-info{{background:#888}}
 table{{width:100%;border-collapse:collapse;margin:12px 0}}
 th,td{{padding:6px 10px;border-bottom:1px solid #ddd;text-align:left;font-size:14px}}
 th{{background:#f5f5f5;cursor:pointer}}
 pre{{background:#f7f7f7;padding:10px;border-radius:6px;overflow:auto}}
 code{{background:#f0f0f0;padding:1px 4px;border-radius:3px}}
 section{{margin:24px 0;padding:10px;background:#fafafa;border-radius:6px}}
</style></head><body>
<h1>Bug Bounty Report — {html.escape(self.target)}</h1>
<p>Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<p>{counts_html}</p>
<h2>Findings ({len(findings)})</h2>
<table id='t'><thead><tr><th>#</th><th>Severity</th><th>CVSS</th><th>✔</th><th>Title</th><th>URL</th><th>Type</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Details</h2>
{''.join(details)}
<script>
document.querySelectorAll('#t th').forEach((th,i)=>{{
  th.addEventListener('click',()=>{{
    const rows=[...document.querySelectorAll('#t tbody tr')];
    rows.sort((a,b)=>a.children[i].innerText.localeCompare(b.children[i].innerText,undefined,{{numeric:true}}));
    const body=document.querySelector('#t tbody'); rows.forEach(r=>body.appendChild(r));
  }});
}});
</script>
</body></html>
"""
        path = os.path.join(self.output_dir, "report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)
        return path

    def generate_report(self):
        findings = self._reportable()
        counts = self._severity_counts(findings)

        # Save raw JSON dump of all findings (including FPs for audit)
        full_path = os.path.join(self.output_dir, "findings", "all_findings.json")
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump([fi.to_dict() for fi in self.findings], f, indent=2)

        md = self._write_markdown(findings, counts)
        self._write_executive(findings, counts)
        self._write_hackerone_json(findings)
        self._write_bugcrowd_json(findings)
        self._write_html(findings, counts)
        return md
