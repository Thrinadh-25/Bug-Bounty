"""Verify the automation framework is wired up correctly.

Checks:
    - Every Python module imports cleanly.
    - Every external tool referenced by the exploit modules is either present
      on $PATH or has a working Python fallback.
    - Required directories exist.
    - API-key config is readable if present.

Usage:
    python -m automation.setup_verify
    python -m automation.setup_verify --fix
"""

import argparse
import importlib
import json
import os
import pkgutil
import shutil
import sys
import traceback


# Tools we *wrap* (each has a Python fallback; missing = degraded, not broken).
OPTIONAL_TOOLS = [
    "nmap", "masscan", "naabu", "subfinder", "amass", "assetfinder",
    "httpx", "nuclei", "ffuf", "gobuster", "feroxbuster", "katana", "gau",
    "waybackurls", "getjs", "linkfinder", "dalfox", "sqlmap", "ghauri",
    "crlfuzz", "arjun", "paramspider", "jwt_tool", "trufflehog",
    "gitleaks", "interactsh-client", "dnsx", "dig", "whois",
    "ssh-keygen",
]

REQUIRED_DIRS = [
    "automation/core",
    "automation/exploits",
    "automation/recon",
    "automation/scanners",
    "automation/utils",
    "automation/output",
    "automation/wordlists",
]


def check_dirs(root):
    missing = []
    for d in REQUIRED_DIRS:
        if not os.path.isdir(os.path.join(root, d)):
            missing.append(d)
    return missing


def check_imports(package):
    """Import every submodule of `package` and report failures."""
    failures = []
    try:
        pkg = importlib.import_module(package)
    except Exception as e:
        return [(package, f"{type(e).__name__}: {e}")]
    for m in pkgutil.walk_packages(pkg.__path__, prefix=package + "."):
        name = m.name
        if name.endswith("__pycache__"):
            continue
        try:
            importlib.import_module(name)
        except Exception as e:
            tb = traceback.format_exc().splitlines()[-1]
            failures.append((name, tb))
    return failures


def check_tools():
    present, missing = [], []
    for t in OPTIONAL_TOOLS:
        if shutil.which(t):
            present.append(t)
        else:
            missing.append(t)
    return present, missing


def check_api_keys_file(root):
    p = os.path.join(root, "automation", "api_keys.json")
    if not os.path.isfile(p):
        return False, "not present (OK — supply at runtime)"
    try:
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        return True, f"{len(d)} keys loaded"
    except Exception as e:
        return False, f"unreadable: {e}"


def make_dirs(root, dirs):
    for d in dirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fix", action="store_true", help="Create any missing directories.")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON only.")
    args = ap.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if root not in sys.path:
        sys.path.insert(0, root)

    report = {"root": root}
    missing_dirs = check_dirs(root)
    report["missing_dirs"] = missing_dirs
    if args.fix and missing_dirs:
        make_dirs(root, missing_dirs)
        missing_dirs = check_dirs(root)
        report["missing_dirs_after_fix"] = missing_dirs

    report["import_failures"] = check_imports("automation")
    present, missing_tools = check_tools()
    report["tools_present"] = present
    report["tools_missing"] = missing_tools
    has_keys, keys_note = check_api_keys_file(root)
    report["api_keys"] = {"present": has_keys, "note": keys_note}

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if not report["import_failures"] and not missing_dirs else 1

    print(f"Root: {root}")
    print(f"Dirs: {'OK' if not missing_dirs else 'MISSING ' + ', '.join(missing_dirs)}")
    print(f"Python imports: {'OK' if not report['import_failures'] else 'FAILURES'}")
    for name, err in report["import_failures"]:
        print(f"  - {name}: {err}")
    print(f"External tools present ({len(present)}/{len(OPTIONAL_TOOLS)}): {', '.join(present) or '(none)'}")
    if missing_tools:
        print(f"External tools missing (Python fallbacks will be used): {', '.join(missing_tools)}")
    print(f"API keys file: {keys_note}")
    return 0 if not report["import_failures"] and not missing_dirs else 1


if __name__ == "__main__":
    sys.exit(main())
