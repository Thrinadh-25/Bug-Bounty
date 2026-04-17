"""Trigger Engine — the brain.

Given a set of findings / recon results, maps them to exploit modules and fires those
modules in parallel (within time-boxes), then collects their Finding objects back into
the main pipeline. Each (target, module) pair is only fired once.
"""

import importlib
import json
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporter import Finding


TRIGGER_MAP = {
    # Port-based
    "port:21":    ["exploits.ftp_anon", "exploits.ftp_bruteforce"],
    "port:22":    ["exploits.ssh_bruteforce", "exploits.ssh_user_enum"],
    "port:25":    ["exploits.smtp_enum", "exploits.smtp_relay"],
    "port:53":    ["scanners.dns_zone"],
    "port:80":    ["exploits.http_methods", "exploits.web_vulns_chain"],
    "port:443":   ["exploits.http_methods", "exploits.web_vulns_chain"],
    "port:445":   ["exploits.smb_enum"],
    "port:3306":  ["exploits.mysql_unauth", "exploits.mysql_bruteforce"],
    "port:5432":  ["exploits.postgres_unauth"],
    "port:6379":  ["exploits.redis_unauth", "exploits.redis_rce"],
    "port:8080":  ["exploits.tomcat_manager", "exploits.spring_actuator"],
    "port:8443":  ["exploits.tomcat_manager"],
    "port:9200":  ["exploits.elasticsearch_unauth"],
    "port:27017": ["exploits.mongo_unauth"],
    "port:11211": ["exploits.memcached_dump"],
    "port:2375":  ["exploits.docker_unauth"],
    "port:2379":  ["exploits.etcd_unauth"],

    # Tech-based
    "tech:WordPress":   ["exploits.wp_enum", "exploits.xmlrpc_attack", "exploits.wp_plugin_cve"],
    "tech:Drupal":      ["exploits.drupalgeddon"],
    "tech:Joomla":      ["exploits.joomla_scan"],
    "tech:Tomcat":      ["exploits.tomcat_manager"],
    "tech:Jenkins":     ["exploits.jenkins_unauth", "exploits.jenkins_rce"],
    "tech:GitLab":      ["exploits.gitlab_enum"],
    "tech:Grafana":     ["exploits.grafana_lfi"],
    "tech:Kibana":      ["exploits.kibana_rce"],
    "tech:Struts":      ["exploits.struts_rce"],
    "tech:Laravel":     ["exploits.laravel_debug", "exploits.laravel_rce"],
    "tech:Spring":      ["exploits.spring_actuator", "exploits.spring4shell"],
    "tech:GraphQL":     ["exploits.graphql_deep"],
    "tech:PHP":         ["exploits.php_info_leak", "exploits.php_type_juggling"],

    # Finding-based
    "finding:sqli":           ["exploits.sqli_confirm_extract"],
    "finding:xss":            ["exploits.xss_confirm"],
    "finding:ssrf":           ["exploits.ssrf_oob_confirm", "exploits.ssrf_internal_pivot"],
    "finding:cors":           ["exploits.cors_confirm"],
    "finding:open_redirect":  ["exploits.redirect_chain"],
    "finding:takeover":       ["exploits.takeover_claim"],
    "finding:crlf":           ["exploits.crlf_exploit"],
    "finding:lfi":            ["exploits.lfi_read_files", "exploits.lfi_to_rce"],
    "finding:xxe":            ["exploits.xxe_read", "exploits.xxe_ssrf"],
    "finding:ssti":           ["exploits.ssti_rce"],
    "finding:idor":           ["exploits.idor_chain"],
    "finding:jwt":            ["exploits.jwt_attacks"],
    "finding:smuggling":      ["exploits.smuggling_confirm"],
    "finding:rate_limit_bypass": ["exploits.rate_limit_abuse"],

    # Secret-based
    "secret:aws_key":         ["exploits.aws_validate", "exploits.aws_enum"],
    "secret:gcp_key":         ["exploits.gcp_validate"],
    "secret:azure_key":       ["exploits.azure_validate"],
    "secret:github_token":    ["exploits.github_token_scope"],
    "secret:jwt_token":       ["exploits.jwt_attacks"],
    "secret:private_key":     ["exploits.private_key_use"],
    "secret:stripe_key":      ["exploits.payment_key_validate"],
    "secret:slack_token":     ["exploits.slack_token_scope"],
    "secret:sendgrid":        ["exploits.email_key_validate"],
    "secret:firebase":        ["exploits.firebase_unauth"],
    "secret:twilio":          ["exploits.twilio_validate"],

    # DNS / Infra
    "dns:zone_transfer":      ["exploits.dns_zone_extract"],
    "dns:wildcard":           ["exploits.vhost_brute_deep"],
    "infra:s3_bucket":        ["exploits.s3_enum", "exploits.s3_write_test"],
    "infra:gcs_bucket":       ["exploits.gcs_enum"],
    "infra:azure_blob":       ["exploits.azure_blob_enum"],
}


def _classify_port(port):
    return f"port:{int(port)}"


def _classify_tech(tech_name):
    return f"tech:{tech_name}"


def _classify_finding(finding):
    ft = (finding.finding_type or "").lower()
    if ft:
        return f"finding:{ft}"
    # Map by title keywords as fallback
    title_l = finding.title.lower()
    for key in ("sqli", "xss", "ssrf", "cors", "open_redirect", "takeover", "crlf",
                "lfi", "xxe", "ssti", "idor", "jwt", "smuggling", "rate_limit"):
        if key in title_l:
            return f"finding:{key}"
    return None


def _classify_secret(secret_type):
    return f"secret:{secret_type}"


class TriggerEngine:
    def __init__(self, reporter, scope, client, opsec=None, session_manager=None,
                 interactsh=None, verifier=None, max_workers=6, module_timeout=60,
                 aggressive=False, logger=print, state_path=None):
        self.reporter = reporter
        self.scope = scope
        self.client = client
        self.opsec = opsec
        self.session_manager = session_manager
        self.interactsh = interactsh
        self.verifier = verifier
        self.max_workers = max_workers
        self.module_timeout = module_timeout
        self.aggressive = aggressive
        self.logger = logger
        self.fired = set()  # (module, target_signature)
        self.events = []
        self.state_path = state_path

    # ---------- signal ingestion ----------
    def from_nmap(self, nmap_results):
        """nmap_results: dict host -> {"ports": [{"port":int, "service":str, ...}, ...]}"""
        signals = []
        for host, data in (nmap_results or {}).items():
            if not self.scope or self.scope.is_in_scope(host):
                for p in data.get("ports", []) if isinstance(data, dict) else []:
                    port = p.get("port") or p.get("portid")
                    if port:
                        signals.append((_classify_port(port), {"host": host, "port": int(port), "service": p.get("service", "")}))
        return signals

    def from_tech(self, tech_results):
        """tech_results: dict url -> {"technologies": [{name: str, ...}, ...]}"""
        signals = []
        for url, data in (tech_results or {}).items():
            techs = data.get("technologies", []) if isinstance(data, dict) else []
            for t in techs:
                name = t.get("name") if isinstance(t, dict) else str(t)
                if name:
                    signals.append((_classify_tech(name), {"url": url, "tech": name}))
        return signals

    def from_findings(self, findings):
        signals = []
        for f in findings or []:
            cls = _classify_finding(f)
            if cls:
                ctx = {
                    "url": f.url, "title": f.title, "severity": f.severity,
                    "payload": f.payload, "param": ",".join(f.params.keys()) if f.params else "",
                    "finding": f,
                }
                signals.append((cls, ctx))
        return signals

    def from_secrets(self, secrets):
        """secrets: list of {'type': 'aws_key', 'value': '...', 'source': url}"""
        signals = []
        for s in secrets or []:
            t = (s.get("type") or "").lower()
            if t:
                signals.append((_classify_secret(t), {"secret": s.get("value"), "source": s.get("source", ""), "secret_type": t}))
        return signals

    def from_infra(self, infra):
        """infra: list of {'kind': 's3_bucket'|'gcs_bucket'|'azure_blob', 'name': ...}"""
        signals = []
        for i in infra or []:
            kind = (i.get("kind") or "").lower()
            if kind:
                signals.append((f"infra:{kind}", dict(i)))
        return signals

    # ---------- dispatch ----------
    def _load_module(self, name):
        try:
            mod = importlib.import_module(name)
            if hasattr(mod, "run"):
                return mod
            return None
        except Exception as e:
            self._log_event("import_fail", name, str(e))
            return None

    def _run_module(self, mod, context):
        try:
            result = mod.run(context, client=self.client, aggressive=self.aggressive, timeout=self.module_timeout)
            if result is None:
                return []
            if isinstance(result, Finding):
                return [result]
            return list(result)
        except Exception as e:
            self._log_event("module_error", mod.__name__, f"{e}\n{traceback.format_exc(limit=3)}")
            return []

    def _target_sig(self, ctx):
        return (ctx.get("host") or "") + "|" + (ctx.get("url") or "") + "|" + (ctx.get("secret") or "")

    def fire(self, signals):
        """Fire modules for a batch of signals. Returns list of Findings."""
        all_findings = []
        jobs = []  # (mod_name, ctx)
        for cls, ctx in signals:
            modules = TRIGGER_MAP.get(cls)
            if not modules:
                continue
            for m in modules:
                sig = (m, self._target_sig(ctx))
                if sig in self.fired:
                    continue
                self.fired.add(sig)
                jobs.append((m, ctx, cls))

        if not jobs:
            return all_findings

        self.logger(f"  [trigger] firing {len(jobs)} module invocations")

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {}
            for m, ctx, cls in jobs:
                mod = self._load_module(m)
                if not mod:
                    continue
                fut = pool.submit(self._run_module, mod, ctx)
                future_map[fut] = (m, ctx, cls)

            for fut in as_completed(future_map, timeout=None):
                m, ctx, cls = future_map[fut]
                try:
                    findings = fut.result(timeout=self.module_timeout)
                except FuturesTimeout:
                    self._log_event("timeout", m, self._target_sig(ctx))
                    continue
                except Exception as e:
                    self._log_event("module_crash", m, str(e))
                    continue
                n_conf = sum(1 for x in findings if getattr(x, "confirmed", False))
                self._log_event("fired", m, f"{cls} -> {len(findings)} findings ({n_conf} confirmed)")
                if self.verifier:
                    for f in findings:
                        self.verifier.verify(f)
                all_findings.extend(findings)

        # collect into reporter
        if self.reporter and all_findings:
            self.reporter.add_findings(all_findings)

        self._save_state()
        return all_findings

    def _log_event(self, kind, module, detail):
        evt = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "kind": kind,
            "module": module,
            "detail": detail,
        }
        self.events.append(evt)
        self.logger(f"  [trigger:{kind}] {module} — {str(detail)[:200]}")

    def _save_state(self):
        if not self.state_path:
            return
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({
                    "fired": sorted([f"{a}||{b}" for a, b in self.fired]),
                    "events": self.events[-500:],
                }, f, indent=2)
        except Exception:
            pass

    def load_state(self, path=None):
        path = path or self.state_path
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for key in data.get("fired", []):
                a, _, b = key.partition("||")
                self.fired.add((a, b))
        except Exception:
            pass
