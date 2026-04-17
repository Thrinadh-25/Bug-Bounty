"""
XSS scanner — reflected, DOM-based indicators, and context-aware payload testing.
Tests URL params, form inputs, and headers.
"""

import re
import sys
import os
from html.parser import HTMLParser
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding


class _ContextParser(HTMLParser):
    """Parser-based context detector. Tracks where a canary string lands:
    html_body, attribute (which attr), javascript, style, comment, event_handler.
    """

    def __init__(self, canary):
        super().__init__(convert_charrefs=False)
        self.canary = canary
        self.contexts = set()
        self.in_script = False
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "script":
            self.in_script = True
        if t == "style":
            self.in_style = True
        for k, v in attrs:
            if v and self.canary in v:
                if k.lower().startswith("on"):
                    self.contexts.add("event_handler")
                elif k.lower() in ("href", "src", "action", "formaction"):
                    self.contexts.add("url_attribute")
                else:
                    self.contexts.add(f"attribute:{k.lower()}")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "script":
            self.in_script = False
        if t == "style":
            self.in_style = False

    def handle_data(self, data):
        if self.canary in data:
            if self.in_script:
                self.contexts.add("javascript")
            elif self.in_style:
                self.contexts.add("style")
            else:
                self.contexts.add("html_body")

    def handle_comment(self, data):
        if self.canary in data:
            self.contexts.add("comment")


def detect_context_parser(html_body, canary):
    """Robust parser-based context detection. Returns a list of contexts."""
    p = _ContextParser(canary)
    try:
        p.feed(html_body)
        p.close()
    except Exception:
        pass
    if not p.contexts and canary in html_body:
        p.contexts.add("unknown")
    return sorted(p.contexts)

# Canary for reflection detection
CANARY = "xss7x3k"

# Context-aware payloads: (name, payload, verification_pattern)
PAYLOADS = [
    # HTML context
    ("HTML tag injection", f"<img src=x onerror={CANARY}>", f"<img src=x onerror={CANARY}>"),
    ("Script injection", f"<script>{CANARY}</script>", f"<script>{CANARY}</script>"),
    ("SVG injection", f"<svg onload={CANARY}>", f"<svg onload={CANARY}>"),
    ("Event handler", f"\" onfocus=\"{CANARY}\" autofocus=\"", f'onfocus="{CANARY}"'),
    ("Body onload", f"<body onload={CANARY}>", f"<body onload={CANARY}>"),
    ("Iframe injection", f"<iframe src=\"javascript:{CANARY}\">", f"<iframe"),

    # Attribute context
    ("Attr breakout double", f'"{CANARY}>', f'"{CANARY}>'),
    ("Attr breakout single", f"'{CANARY}>", f"'{CANARY}>"),
    ("Attr event handler", f'" onmouseover="{CANARY}"', f'onmouseover="{CANARY}"'),

    # JavaScript context
    ("JS string breakout", f"';{CANARY}//", f"';{CANARY}//"),
    ("JS template literal", f"${{`{CANARY}`}}", CANARY),
    ("JS double quote break", f'";{CANARY}//', f'";{CANARY}//'),

    # Filter bypass payloads
    ("Case bypass", f"<ScRiPt>{CANARY}</sCrIpT>", CANARY),
    ("Null byte", f"<%00script>{CANARY}</script>", CANARY),
    ("Double encoding", f"%253Cscript%253E{CANARY}%253C/script%253E", CANARY),
    ("Unicode", f"<\u0073cript>{CANARY}</script>", CANARY),
    ("No quotes event", f"<img src=x onerror={CANARY}>", f"onerror={CANARY}"),
    ("Backtick payload", f"<img src=x onerror=`{CANARY}`>", CANARY),
]

# Minimal payloads for quick scanning
QUICK_PAYLOADS = [
    ("Reflection check", CANARY, CANARY),
    ("HTML injection", f"<b>{CANARY}</b>", f"<b>{CANARY}</b>"),
    ("Tag injection", f"<img src=x onerror={CANARY}>", f"<img src=x onerror={CANARY}>"),
    ("Script injection", f"<script>{CANARY}</script>", f"<script>{CANARY}</script>"),
    ("Attr breakout", f'"><img src=x onerror={CANARY}>', f"<img src=x onerror={CANARY}>"),
]

# DOM-based XSS sinks and sources to look for in JS
DOM_SINKS = [
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"new\s+Function\s*\(",
    r"\.src\s*=",
    r"\.href\s*=",
    r"location\s*=",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"window\.open\s*\(",
    r"\.setAttribute\s*\(\s*['\"]on",
]

DOM_SOURCES = [
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"location\.search",
    r"location\.hash",
    r"location\.href",
    r"location\.pathname",
    r"window\.name",
    r"document\.cookie",
    r"history\.pushState",
    r"history\.replaceState",
    r"localStorage\.",
    r"sessionStorage\.",
]


def detect_context(html, canary):
    """Detect where the canary appears in the HTML — determines which payloads to prioritize."""
    contexts = []

    # Check if in HTML tag attribute
    if re.search(rf'(value|href|src|action|data)\s*=\s*["\'][^"\']*{re.escape(canary)}', html, re.IGNORECASE):
        contexts.append("attribute")

    # Check if inside <script> block
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
    for block in script_blocks:
        if canary in block:
            contexts.append("javascript")

    # Check if in HTML body (not inside a tag)
    if canary in re.sub(r"<[^>]+>", "", html):
        contexts.append("html_body")

    # Check if in a comment
    if re.search(rf"<!--[^>]*{re.escape(canary)}[^>]*-->", html):
        contexts.append("comment")

    if not contexts and canary in html:
        contexts.append("unknown")

    return contexts


def check_dom_xss(html):
    """Check for DOM-based XSS patterns in JavaScript."""
    findings_info = []
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
    full_js = "\n".join(script_blocks)

    sinks_found = []
    sources_found = []

    for pattern in DOM_SINKS:
        matches = re.findall(pattern, full_js)
        if matches:
            sinks_found.append(pattern)

    for pattern in DOM_SOURCES:
        matches = re.findall(pattern, full_js)
        if matches:
            sources_found.append(pattern)

    if sinks_found and sources_found:
        findings_info.append({
            "sinks": sinks_found,
            "sources": sources_found,
        })

    return findings_info


def test_param(url, param, original_value, client, quick=False):
    """Test a single parameter for XSS. Returns list of Findings."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    payloads = QUICK_PAYLOADS if quick else PAYLOADS

    # First check: does the param reflect at all?
    test_params = dict(params)
    test_params[param] = [CANARY]
    query = urlencode(test_params, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

    resp = client.get(test_url)
    if not resp or CANARY not in resp.text:
        return findings  # Not reflected, skip

    # Prefer parser-based context detection (fallback: regex)
    contexts = detect_context_parser(resp.text, CANARY) or detect_context(resp.text, CANARY)

    # Test payloads
    for name, payload, verify in payloads:
        test_params = dict(params)
        test_params[param] = [payload]
        query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

        resp = client.get(test_url)
        if not resp:
            continue

        if verify in resp.text:
            # Check if it's actually executable (not encoded)
            encoded_check = resp.text.count("&lt;") + resp.text.count("&gt;") + resp.text.count("&#")
            raw_check = resp.text.count(verify)

            if raw_check > 0:
                severity = "high"
                if "<script>" in payload or "onerror=" in payload or "onload=" in payload:
                    severity = "critical" if verify in resp.text else "high"

                findings.append(Finding(
                    title=f"Reflected XSS in '{param}' ({name})",
                    severity=severity,
                    description=(
                        f"Parameter '{param}' reflects unsanitized input in {', '.join(contexts)} context. "
                        f"Payload type: {name}."
                    ),
                    url=test_url,
                    evidence=(
                        f"Payload: {payload}\n"
                        f"Reflection context: {', '.join(contexts)}\n"
                        f"Verified: '{verify}' found in response"
                    ),
                    remediation=(
                        "Encode output based on context: HTML entities for HTML, "
                        "JS encoding for JavaScript, URL encoding for URLs. "
                        "Implement Content-Security-Policy header."
                    ),
                ))
                return findings  # Confirmed, no need for more payloads

    return findings


def scan_url(url, quick=False, verbose=True):
    """Scan all parameters in a URL for XSS."""
    client = HTTPClient(rate_limit=0.3, timeout=10, retries=1)
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        # Still check for DOM XSS
        resp = client.get(url)
        if resp:
            dom_issues = check_dom_xss(resp.text)
            for issue in dom_issues:
                findings.append(Finding(
                    title="Potential DOM-based XSS",
                    severity="medium",
                    description="JavaScript contains both user-controlled sources and dangerous sinks.",
                    url=url,
                    evidence=f"Sources: {issue['sources'][:3]}\nSinks: {issue['sinks'][:3]}",
                    remediation="Sanitize DOM inputs. Avoid innerHTML, eval(), and document.write with user data.",
                ))
        return findings

    for param, values in params.items():
        original_value = values[0] if values else ""
        if verbose:
            print(f"    Testing param: {param}", flush=True)

        f = test_param(url, param, original_value, client, quick)
        findings.extend(f)
        if f and verbose:
            print(f"      [{f[0].severity.upper()}] XSS found!")

    # Also check DOM XSS
    resp = client.get(url)
    if resp:
        dom_issues = check_dom_xss(resp.text)
        for issue in dom_issues:
            findings.append(Finding(
                title="Potential DOM-based XSS",
                severity="medium",
                description="JavaScript contains user-controlled sources flowing into dangerous sinks.",
                url=url,
                evidence=f"Sources: {issue['sources'][:3]}\nSinks: {issue['sinks'][:3]}",
                remediation="Sanitize DOM inputs before passing to sinks.",
            ))

    return findings


def scan_multiple(urls, quick=False, verbose=True):
    """Scan multiple URLs for XSS."""
    all_findings = []
    for url in urls:
        if verbose:
            print(f"  [{url[:80]}] testing XSS...", flush=True)
        findings = scan_url(url, quick, verbose)
        all_findings.extend(findings)
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xss.py <url_with_params>")
        print("Example: python xss.py 'https://example.com/search?q=test'")
        sys.exit(1)
    url = sys.argv[1]
    print(f"\n[*] XSS scan: {url}\n")
    findings = scan_url(url)
    if not findings:
        print("\n  No XSS found")
    for f in findings:
        print(f"\n  [{f.severity.upper()}] {f.title}")
        print(f"  {f.evidence}")
