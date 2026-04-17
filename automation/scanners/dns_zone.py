"""
DNS enumeration — zone transfer attempts, record enumeration, and DNS misconfigurations.
"""

import subprocess
import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporter import Finding


def get_nameservers(domain):
    """Get nameservers for a domain."""
    try:
        import dns.resolver
        ns_records = dns.resolver.resolve(domain, "NS")
        return [str(rdata.target).rstrip(".") for rdata in ns_records]
    except Exception:
        # Fallback: use nslookup
        try:
            result = subprocess.run(
                ["nslookup", "-type=NS", domain],
                capture_output=True, text=True, timeout=10
            )
            nameservers = []
            for line in result.stdout.split("\n"):
                if "nameserver" in line.lower():
                    parts = line.split("=")
                    if len(parts) > 1:
                        nameservers.append(parts[-1].strip().rstrip("."))
            return nameservers
        except Exception:
            return []


def attempt_zone_transfer(domain, nameserver):
    """Attempt AXFR zone transfer."""
    try:
        import dns.query
        import dns.zone
        z = dns.query.xfr(nameserver, domain, timeout=10)
        zone = dns.zone.from_xfr(z)
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{domain} {rdataset.rdtype.name} {rdata}")
        return records
    except Exception:
        pass

    # Fallback: dig or host command
    for cmd in [
        ["dig", f"@{nameserver}", domain, "AXFR"],
        ["host", "-t", "AXFR", domain, nameserver],
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if "Transfer failed" not in result.stdout and "refused" not in result.stdout.lower():
                lines = [l for l in result.stdout.split("\n") if l.strip() and not l.startswith(";")]
                if len(lines) > 2:
                    return lines
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


def enumerate_records(domain):
    """Enumerate common DNS record types."""
    records = {}
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "SOA", "SRV", "CAA", "NS"]

    try:
        import dns.resolver
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
    except ImportError:
        # Fallback to nslookup
        for rtype in ["A", "MX", "TXT", "NS", "CNAME"]:
            try:
                result = subprocess.run(
                    ["nslookup", f"-type={rtype}", domain],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    records[rtype] = result.stdout.strip().split("\n")
            except Exception:
                pass

    return records


def check_spf_dmarc(domain):
    """Check for SPF and DMARC records — missing = email spoofing risk."""
    issues = []

    try:
        import dns.resolver

        # SPF check
        has_spf = False
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            for rdata in txt_records:
                txt = str(rdata).lower()
                if "v=spf1" in txt:
                    has_spf = True
                    if "+all" in txt:
                        issues.append(("SPF +all", "SPF record uses +all which allows any server to send email"))
                    if "~all" in txt:
                        issues.append(("SPF ~all", "SPF record uses ~all (softfail) instead of -all (hardfail)"))
        except Exception:
            pass
        if not has_spf:
            issues.append(("No SPF", "No SPF record found — email spoofing possible"))

        # DMARC check
        has_dmarc = False
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in dmarc_records:
                txt = str(rdata).lower()
                if "v=dmarc1" in txt:
                    has_dmarc = True
                    if "p=none" in txt:
                        issues.append(("DMARC p=none", "DMARC policy is 'none' — no email authentication enforcement"))
        except Exception:
            pass
        if not has_dmarc:
            issues.append(("No DMARC", "No DMARC record found — email spoofing not prevented"))

    except ImportError:
        pass

    return issues


def scan(domain, verbose=True):
    """Full DNS security scan."""
    findings = []

    # Get nameservers
    if verbose:
        print(f"  Getting nameservers for {domain}...")
    nameservers = get_nameservers(domain)
    if verbose:
        print(f"  Nameservers: {', '.join(nameservers) if nameservers else 'none found'}")

    # Attempt zone transfer
    if verbose:
        print(f"\n  Attempting zone transfer...")
    for ns in nameservers:
        if verbose:
            print(f"    {ns}...", end=" ", flush=True)
        records = attempt_zone_transfer(domain, ns)
        if records:
            findings.append(Finding(
                title=f"DNS Zone Transfer Allowed ({ns})",
                severity="high",
                description=f"Nameserver {ns} allows zone transfer (AXFR) — full DNS zone is exposed.",
                url=domain,
                evidence=f"Zone transfer from {ns}: {len(records)} records\nSample: {'; '.join(records[:5])}",
                remediation="Restrict zone transfers to authorized secondary nameservers only.",
            ))
            if verbose:
                print(f"VULNERABLE! ({len(records)} records)")
        elif verbose:
            print("refused (good)")

    # Enumerate records
    if verbose:
        print(f"\n  Enumerating DNS records...")
    records = enumerate_records(domain)
    if verbose:
        for rtype, values in records.items():
            print(f"    {rtype}: {', '.join(str(v)[:60] for v in values[:3])}")

    # SPF/DMARC check
    if verbose:
        print(f"\n  Checking SPF/DMARC...")
    email_issues = check_spf_dmarc(domain)
    for issue_name, issue_desc in email_issues:
        severity = "medium" if "No " in issue_name else "low"
        findings.append(Finding(
            title=f"Email Security: {issue_name}",
            severity=severity,
            description=issue_desc,
            url=domain,
            evidence=issue_name,
            remediation="Configure proper SPF (-all) and DMARC (p=reject) records.",
        ))
        if verbose:
            print(f"    [{severity.upper()}] {issue_name}: {issue_desc}")

    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_zone.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    print(f"\n[*] DNS security scan: {domain}\n")
    scan(domain)
