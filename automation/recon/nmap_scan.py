"""
Nmap integration — port scanning, service detection, script scanning.
Falls back to Python socket scan if nmap not installed.
"""

import subprocess
import socket
import sys
import os
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def nmap_available():
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def nmap_scan(target, ports="--top-ports 1000", extra_args="", timeout=300):
    """Run nmap scan. Returns parsed results dict."""
    cmd = f"nmap -sV -sC {ports} {extra_args} -oX - {target}"
    try:
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=timeout
        )
        return parse_nmap_xml(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}


def parse_nmap_xml(xml_output):
    """Parse nmap XML output into a clean dict."""
    results = {"hosts": []}

    # Simple regex parsing (avoids xml.etree for robustness)
    host_blocks = re.findall(r"<host\b.*?</host>", xml_output, re.DOTALL)

    for block in host_blocks:
        host = {"ip": "", "hostname": "", "ports": [], "os": ""}

        ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
        if ip_match:
            host["ip"] = ip_match.group(1)

        hostname_match = re.search(r'<hostname name="([^"]+)"', block)
        if hostname_match:
            host["hostname"] = hostname_match.group(1)

        port_blocks = re.findall(r"<port\b.*?</port>", block, re.DOTALL)
        for pb in port_blocks:
            port_info = {}
            port_match = re.search(r'protocol="([^"]+)" portid="([^"]+)"', pb)
            if port_match:
                port_info["protocol"] = port_match.group(1)
                port_info["port"] = int(port_match.group(2))

            state_match = re.search(r'<state state="([^"]+)"', pb)
            if state_match:
                port_info["state"] = state_match.group(1)

            service_match = re.search(
                r'<service name="([^"]*)".*?product="([^"]*)".*?version="([^"]*)"', pb
            )
            if service_match:
                port_info["service"] = service_match.group(1)
                port_info["product"] = service_match.group(2)
                port_info["version"] = service_match.group(3)
            else:
                svc = re.search(r'<service name="([^"]*)"', pb)
                port_info["service"] = svc.group(1) if svc else ""
                port_info["product"] = ""
                port_info["version"] = ""

            # Grab script output
            scripts = re.findall(r'<script id="([^"]+)" output="([^"]*)"', pb)
            port_info["scripts"] = {s[0]: s[1] for s in scripts}

            if port_info.get("state") == "open":
                host["ports"].append(port_info)

        results["hosts"].append(host)

    return results


def socket_scan(target, ports=None, timeout_per_port=1, max_workers=50):
    """Fallback: Python socket-based port scan."""
    if ports is None:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8000,
            8080, 8443, 8888, 9090, 9200, 27017,
        ]

    open_ports = []

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_per_port)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_port, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports)


def scan(target, scan_type="default", verbose=True):
    """
    Smart port scan — uses nmap if available, falls back to socket scan.
    scan_type: 'quick', 'default', 'full', 'udp', 'vuln'
    """
    if verbose:
        print(f"  Target: {target}")

    if nmap_available():
        if verbose:
            print("  Using: nmap")

        scan_configs = {
            "quick": ("--top-ports 100", "-T4"),
            "default": ("--top-ports 1000", "-sV -sC"),
            "full": ("-p-", "-sV -sC -T4"),
            "udp": ("--top-ports 100", "-sU -sV"),
            "vuln": ("--top-ports 1000", "-sV --script=vuln"),
        }
        ports, extra = scan_configs.get(scan_type, scan_configs["default"])
        results = nmap_scan(target, ports, extra)

        if verbose and "hosts" in results:
            for host in results["hosts"]:
                print(f"\n  Host: {host['ip']} ({host['hostname']})")
                for p in host["ports"]:
                    svc = f"{p.get('product', '')} {p.get('version', '')}".strip()
                    print(f"    {p['port']}/{p['protocol']}  {p.get('service', '')}  {svc}")
                    for script_id, output in p.get("scripts", {}).items():
                        print(f"      |_ {script_id}: {output[:100]}")

        return results
    else:
        if verbose:
            print("  Using: socket scan (install nmap for better results)")

        open_ports = socket_scan(target)
        if verbose:
            print(f"  Open ports: {open_ports}")

        return {
            "hosts": [{
                "ip": target,
                "hostname": target,
                "ports": [{"port": p, "protocol": "tcp", "state": "open", "service": "", "product": "", "version": ""} for p in open_ports],
                "os": "",
            }]
        }


def scan_multiple(targets, scan_type="quick", verbose=True):
    """Scan multiple targets."""
    all_results = {}
    for target in targets:
        if verbose:
            print(f"\n  [{target}] scanning ports...", flush=True)
        all_results[target] = scan(target, scan_type, verbose)
    return all_results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_scan.py <target> [quick|default|full|vuln]")
        sys.exit(1)
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "default"
    print(f"\n[*] Port scan: {target} ({scan_type})\n")
    scan(target, scan_type)
