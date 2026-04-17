"""
SSL/TLS analyzer — certificate validation, expiry, and protocol checks.
"""

import ssl
import socket
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporter import Finding


def analyze(hostname, port=443):
    """Analyze SSL/TLS configuration for a host. Returns list of Findings."""
    findings = []

    # Get certificate info
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            title="SSL Certificate Verification Failed",
            severity="high",
            description=f"Certificate validation failed: {e}",
            url=f"https://{hostname}:{port}",
            evidence=str(e),
            remediation="Fix the certificate — ensure it's valid, not expired, and matches the hostname.",
        ))
        # Try again without verification to get more info
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    protocol = ssock.version()
                    cipher = ssock.cipher()
        except Exception:
            return findings
    except Exception as e:
        findings.append(Finding(
            title="SSL Connection Failed",
            severity="info",
            description=f"Could not establish SSL connection to {hostname}:{port}",
            url=f"https://{hostname}:{port}",
            evidence=str(e),
        ))
        return findings

    url = f"https://{hostname}:{port}"

    # Check certificate expiry
    if cert:
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                if days_left < 0:
                    findings.append(Finding(
                        title="SSL Certificate Expired",
                        severity="high",
                        description=f"Certificate expired {abs(days_left)} days ago.",
                        url=url,
                        evidence=f"Expiry: {not_after}",
                        remediation="Renew the certificate immediately.",
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        title="SSL Certificate Expiring Soon",
                        severity="medium",
                        description=f"Certificate expires in {days_left} days.",
                        url=url,
                        evidence=f"Expiry: {not_after}",
                        remediation="Renew the certificate before it expires.",
                    ))
            except ValueError:
                pass

        # Check for wildcard cert
        san = cert.get("subjectAltName", ())
        for type_, value in san:
            if value.startswith("*"):
                findings.append(Finding(
                    title="Wildcard SSL Certificate",
                    severity="info",
                    description="Wildcard certificate in use — if private key is compromised, all subdomains are affected.",
                    url=url,
                    evidence=f"SAN: {value}",
                ))
                break

    # Check protocol version
    if protocol:
        if "TLSv1.0" in protocol or "TLSv1.1" in protocol:
            findings.append(Finding(
                title=f"Outdated TLS Version: {protocol}",
                severity="medium",
                description=f"Server supports {protocol} which is deprecated and has known vulnerabilities.",
                url=url,
                evidence=f"Protocol: {protocol}",
                remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3.",
            ))
        elif "SSLv" in protocol:
            findings.append(Finding(
                title=f"Insecure Protocol: {protocol}",
                severity="high",
                description=f"Server supports {protocol} — critically insecure.",
                url=url,
                evidence=f"Protocol: {protocol}",
                remediation="Disable all SSL versions. Use TLSv1.2 or TLSv1.3 only.",
            ))

    # Check cipher strength
    if cipher:
        cipher_name = cipher[0]
        cipher_bits = cipher[2] if len(cipher) > 2 else 0
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
        for weak in weak_ciphers:
            if weak.lower() in cipher_name.lower():
                findings.append(Finding(
                    title=f"Weak Cipher: {cipher_name}",
                    severity="medium",
                    description=f"Negotiated cipher {cipher_name} is considered weak.",
                    url=url,
                    evidence=f"Cipher: {cipher_name} ({cipher_bits} bits)",
                    remediation="Disable weak ciphers. Use AES-GCM or ChaCha20-Poly1305.",
                ))
                break
        if cipher_bits and cipher_bits < 128:
            findings.append(Finding(
                title=f"Low Cipher Strength: {cipher_bits}-bit",
                severity="medium",
                description=f"Cipher uses only {cipher_bits}-bit encryption.",
                url=url,
                evidence=f"Cipher: {cipher_name} ({cipher_bits} bits)",
                remediation="Use ciphers with at least 128-bit strength.",
            ))

    return findings


def scan_multiple(hosts, verbose=True):
    """Scan multiple hosts for SSL issues."""
    all_findings = []
    for host in hosts:
        hostname = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if verbose:
            print(f"  [{hostname}] checking SSL...", flush=True)
        findings = analyze(hostname)
        all_findings.extend(findings)
        if verbose:
            for f in findings:
                print(f"    [{f.severity.upper()}] {f.title}")
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ssl_scan.py <hostname>")
        sys.exit(1)
    hostname = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]
    print(f"\n[*] SSL analysis: {hostname}\n")
    findings = analyze(hostname)
    if not findings:
        print("  No SSL issues found")
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}: {f.evidence}")
