"""
Asset monitor — run recon periodically and diff against previous results.
Alerts on new subdomains, changed hosts, new endpoints.
"""

import json
import os
import sys
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recon.subdomains import enumerate as enum_subdomains
from recon.live_check import check_hosts


def load_previous(filepath):
    """Load previous scan results."""
    if os.path.exists(filepath):
        with open(filepath) as f:
            return json.load(f)
    return None


def save_current(filepath, data):
    """Save current scan results."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def diff_results(previous, current, key="items"):
    """Compare two result sets and return new/removed items."""
    prev_set = set(previous.get(key, []))
    curr_set = set(current.get(key, []))

    return {
        "new": sorted(curr_set - prev_set),
        "removed": sorted(prev_set - curr_set),
        "unchanged": len(curr_set & prev_set),
        "total_previous": len(prev_set),
        "total_current": len(curr_set),
    }


def monitor_target(domain, output_dir=None, verbose=True):
    """Run monitoring scan and diff against previous results."""
    if not output_dir:
        safe_name = domain.replace(".", "_")
        output_dir = os.path.join(os.path.dirname(__file__), "output", f"{safe_name}_monitor")
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    changes = {"domain": domain, "timestamp": timestamp, "alerts": []}

    # --- Subdomain monitoring ---
    if verbose:
        print(f"\n[*] Subdomain monitoring: {domain}")
    subdomains = enum_subdomains(domain, verbose=verbose)

    sub_file = os.path.join(output_dir, "subdomains_latest.json")
    previous_subs = load_previous(sub_file)

    current_sub_data = {"items": subdomains, "timestamp": timestamp}

    if previous_subs:
        diff = diff_results(previous_subs, current_sub_data)
        if diff["new"]:
            changes["alerts"].append({
                "type": "NEW_SUBDOMAINS",
                "severity": "high",
                "message": f"{len(diff['new'])} new subdomain(s) discovered!",
                "items": diff["new"],
            })
            if verbose:
                print(f"\n  [!] NEW SUBDOMAINS: {len(diff['new'])}")
                for s in diff["new"]:
                    print(f"    + {s}")
        if diff["removed"]:
            changes["alerts"].append({
                "type": "REMOVED_SUBDOMAINS",
                "severity": "info",
                "message": f"{len(diff['removed'])} subdomain(s) no longer resolving",
                "items": diff["removed"],
            })
        if verbose:
            print(f"\n  Total: {diff['total_current']} (was {diff['total_previous']})")
            print(f"  New: {len(diff['new'])}, Removed: {len(diff['removed'])}")
    else:
        if verbose:
            print(f"\n  First scan — {len(subdomains)} subdomains recorded as baseline")

    save_current(sub_file, current_sub_data)

    # --- Live host monitoring ---
    if verbose:
        print(f"\n[*] Live host monitoring...")
    live_results = check_hosts(subdomains, verbose=verbose)
    live_hosts = [r["url"] for r in live_results]

    live_file = os.path.join(output_dir, "live_hosts_latest.json")
    previous_live = load_previous(live_file)

    current_live_data = {"items": live_hosts, "timestamp": timestamp, "details": live_results}

    if previous_live:
        diff = diff_results(previous_live, current_live_data)
        if diff["new"]:
            changes["alerts"].append({
                "type": "NEW_LIVE_HOSTS",
                "severity": "high",
                "message": f"{len(diff['new'])} new live host(s)!",
                "items": diff["new"],
            })
            if verbose:
                print(f"\n  [!] NEW LIVE HOSTS: {len(diff['new'])}")
                for h in diff["new"]:
                    print(f"    + {h}")
    else:
        if verbose:
            print(f"  First scan — {len(live_hosts)} live hosts recorded")

    save_current(live_file, current_live_data)

    # --- Save change log ---
    log_file = os.path.join(output_dir, f"changes_{timestamp}.json")
    save_current(log_file, changes)

    # Summary
    alert_count = len(changes["alerts"])
    if verbose:
        print(f"\n{'='*50}")
        print(f"  Monitor complete: {domain}")
        print(f"  Alerts: {alert_count}")
        for alert in changes["alerts"]:
            print(f"    [{alert['severity'].upper()}] {alert['message']}")
        print(f"  Results saved to: {output_dir}")
        print(f"{'='*50}\n")

    return changes


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python monitor.py <domain>")
        print("\nRun periodically (e.g., via cron) to detect changes:")
        print("  0 */6 * * * python monitor.py example.com")
        sys.exit(1)
    domain = sys.argv[1]
    monitor_target(domain)
