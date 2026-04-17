"""
WAF detection and fingerprinting — identify which WAF protects a target
so we can use the right bypass techniques.
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient

# WAF signatures: header patterns, cookie names, response body patterns
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"Server": "cloudflare", "CF-RAY": ""},
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body": [r"Attention Required! \| Cloudflare", r"cloudflare-static"],
        "codes": [403, 503],
    },
    "AWS WAF": {
        "headers": {"x-amzn-RequestId": ""},
        "cookies": ["awsalb", "awsalbcors"],
        "body": [r"<title>ERROR: The request could not be satisfied</title>"],
        "codes": [403],
    },
    "Akamai": {
        "headers": {"Server": "AkamaiGHost", "X-Akamai-Transformed": ""},
        "cookies": ["akamai_", "ak_bmsc"],
        "body": [r"Access Denied.*Reference #", r"AkamaiGHost"],
        "codes": [403],
    },
    "Imperva/Incapsula": {
        "headers": {"X-CDN": "Incapsula", "X-Iinfo": ""},
        "cookies": ["visid_incap_", "incap_ses_", "nlbi_"],
        "body": [r"Incapsula incident ID", r"_Incapsula_Resource"],
        "codes": [403],
    },
    "Sucuri": {
        "headers": {"Server": "Sucuri", "X-Sucuri-ID": ""},
        "cookies": ["sucuri_cloudproxy_"],
        "body": [r"Sucuri Website Firewall", r"Access Denied - Sucuri"],
        "codes": [403],
    },
    "ModSecurity": {
        "headers": {"Server": "ModSecurity"},
        "cookies": [],
        "body": [r"ModSecurity", r"Mod_Security", r"NOYB"],
        "codes": [403, 406],
    },
    "F5 BIG-IP ASM": {
        "headers": {"Server": "BigIP", "X-WA-Info": ""},
        "cookies": ["TS", "BIGipServer", "f5_cspm"],
        "body": [r"The requested URL was rejected", r"support ID"],
        "codes": [403],
    },
    "Barracuda": {
        "headers": {"Server": "Barracuda"},
        "cookies": ["barra_counter_session"],
        "body": [r"Barracuda Web Application Firewall"],
        "codes": [403],
    },
    "Fortinet/FortiWeb": {
        "headers": {"Server": "FortiWeb"},
        "cookies": ["FORTIWAFSID"],
        "body": [r"FortiWeb", r"\.fwptt"],
        "codes": [403],
    },
    "DenyAll": {
        "headers": {},
        "cookies": ["sessioncookie"],
        "body": [r"Condition Intercepted"],
        "codes": [403],
    },
    "Wallarm": {
        "headers": {"Server": "nginx-wallarm"},
        "cookies": [],
        "body": [r"wallarm"],
        "codes": [403],
    },
    "Reblaze": {
        "headers": {"Server": "Reblaze Secure Web Gateway"},
        "cookies": ["rbzid"],
        "body": [r"Access Denied.*Reblaze"],
        "codes": [403],
    },
}

# Trigger payloads — these should trigger WAF blocks
TRIGGER_PAYLOADS = [
    "/?test=<script>alert(1)</script>",
    "/?test=' OR 1=1 --",
    "/?test=../../etc/passwd",
    "/?test=; ls -la",
    "/?test={{7*7}}",
    "/?test=<img src=x onerror=alert(1)>",
]


def detect_waf(url, verbose=True):
    """Detect WAF on a target. Returns WAF name and confidence."""
    client = HTTPClient(timeout=10, retries=1)

    # Normal request first
    normal_resp = client.get(url)
    if not normal_resp:
        return {"waf": "Unknown", "confidence": "low", "evidence": "Could not connect"}

    detected = {}

    # Check normal response for WAF signatures
    _check_response(normal_resp, detected)

    # Send trigger payloads to provoke WAF
    for payload in TRIGGER_PAYLOADS:
        trigger_url = url.rstrip("/") + payload
        resp = client.get(trigger_url)
        if resp:
            _check_response(resp, detected)
            # If we got blocked, that's a strong signal
            if resp.status_code in (403, 406, 429, 503):
                _check_response(resp, detected, weight=2)

    if not detected:
        if verbose:
            print("  No WAF detected (or WAF is transparent)")
        return {"waf": "None/Transparent", "confidence": "medium", "evidence": "No WAF signatures found"}

    # Return highest confidence detection
    best_waf = max(detected.items(), key=lambda x: x[1]["score"])
    result = {
        "waf": best_waf[0],
        "confidence": "high" if best_waf[1]["score"] >= 3 else "medium",
        "evidence": best_waf[1]["evidence"],
        "all_detected": {k: v["score"] for k, v in detected.items()},
    }

    if verbose:
        print(f"  WAF detected: {result['waf']} (confidence: {result['confidence']})")
        if len(detected) > 1:
            print(f"  Other signals: {', '.join(k for k in detected if k != result['waf'])}")

    return result


def _check_response(resp, detected, weight=1):
    """Check a response against all WAF signatures."""
    for waf_name, sigs in WAF_SIGNATURES.items():
        score = 0
        evidence = []

        # Header checks
        for header, expected_value in sigs.get("headers", {}).items():
            actual = resp.headers.get(header, "")
            if actual:
                if not expected_value or expected_value.lower() in actual.lower():
                    score += 2 * weight
                    evidence.append(f"Header {header}: {actual}")

        # Cookie checks
        cookie_names = [c.name.lower() for c in resp.cookies] if resp.cookies else []
        for cookie_pattern in sigs.get("cookies", []):
            for cn in cookie_names:
                if cookie_pattern.lower() in cn:
                    score += 1 * weight
                    evidence.append(f"Cookie: {cn}")

        # Body checks
        for pattern in sigs.get("body", []):
            if re.search(pattern, resp.text[:10000], re.IGNORECASE):
                score += 2 * weight
                evidence.append(f"Body match: {pattern}")

        # Status code
        if resp.status_code in sigs.get("codes", []):
            score += 1 * weight

        if score > 0:
            if waf_name not in detected:
                detected[waf_name] = {"score": 0, "evidence": []}
            detected[waf_name]["score"] += score
            detected[waf_name]["evidence"].extend(evidence)


def detect_multiple(urls, verbose=True):
    results = {}
    for url in urls:
        if verbose:
            print(f"\n  [{url}]", flush=True)
        results[url] = detect_waf(url, verbose)
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python waf_detect.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] WAF detection: {url}\n")
    detect_waf(url)
