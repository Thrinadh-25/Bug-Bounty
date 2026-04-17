"""
Technology fingerprinting — detect frameworks, servers, CDNs, and CMS from HTTP responses.
No external tools needed, pure header/body analysis.
"""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient

# Fingerprint database: (category, name, detection_method)
HEADER_FINGERPRINTS = {
    "Server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "microsoft-iis": "IIS",
        "litespeed": "LiteSpeed",
        "gunicorn": "Gunicorn",
        "openresty": "OpenResty",
    },
    "X-Powered-By": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js",
        "next.js": "Next.js",
        "flask": "Flask",
        "django": "Django",
        "ruby": "Ruby",
    },
    "X-Generator": {
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
    },
}

BODY_FINGERPRINTS = [
    ("WordPress", [r"wp-content/", r"wp-includes/", r'<meta name="generator" content="WordPress']),
    ("Drupal", [r"drupal.js", r'jQuery\.extend\(Drupal', r"sites/default/files"]),
    ("Joomla", [r"/media/jui/", r"Joomla!", r"/components/com_"]),
    ("React", [r"react\.production\.min\.js", r"_reactRootContainer", r'"react"', r"__NEXT_DATA__"]),
    ("Angular", [r"ng-version=", r"angular\.min\.js", r"ng-app="]),
    ("Vue.js", [r"vue\.min\.js", r"vue\.runtime", r"__vue__", r"v-cloak"]),
    ("jQuery", [r"jquery[\.-][\d]+.*\.js", r"jQuery v"]),
    ("Bootstrap", [r"bootstrap\.min\.(css|js)", r"bootstrap@"]),
    ("Cloudflare", [r"cf-ray", r"cloudflare"]),
    ("AWS S3", [r"AmazonS3", r"s3\.amazonaws\.com"]),
    ("Firebase", [r"firebaseapp\.com", r"firebase\.js", r"__firebase"]),
    ("Shopify", [r"cdn\.shopify\.com", r"Shopify\.theme"]),
    ("Vercel", [r"vercel", r"x-vercel-id"]),
    ("Netlify", [r"netlify", r"x-nf-request-id"]),
]

COOKIE_FINGERPRINTS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java/Tomcat",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "rack.session": "Ruby/Rack",
    "connect.sid": "Express.js",
    "_cfuvid": "Cloudflare",
    "wp-settings": "WordPress",
}


def detect_from_headers(headers):
    techs = {}
    for header_name, patterns in HEADER_FINGERPRINTS.items():
        value = headers.get(header_name, "").lower()
        if value:
            for pattern, tech_name in patterns.items():
                if pattern in value:
                    techs[tech_name] = {"source": f"header:{header_name}", "value": value}
    return techs


def detect_from_body(body):
    techs = {}
    body_lower = body[:50000]  # only scan first 50k chars
    for tech_name, patterns in BODY_FINGERPRINTS:
        for pattern in patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                techs[tech_name] = {"source": "body", "pattern": pattern}
                break
    return techs


def detect_from_cookies(cookies):
    techs = {}
    cookie_names = [c.name for c in cookies] if hasattr(cookies, '__iter__') else []
    for cookie_name, tech_name in COOKIE_FINGERPRINTS.items():
        for cn in cookie_names:
            if cookie_name.lower() in cn.lower():
                techs[tech_name] = {"source": "cookie", "cookie": cn}
    return techs


def detect_from_response_headers(headers):
    """Extra detections from misc headers."""
    techs = {}
    if "X-Vercel-Id" in headers:
        techs["Vercel"] = {"source": "header:X-Vercel-Id"}
    if "X-Amz-Cf-Id" in headers:
        techs["AWS CloudFront"] = {"source": "header:X-Amz-Cf-Id"}
    if "CF-RAY" in headers or "cf-ray" in {k.lower() for k in headers}:
        techs["Cloudflare"] = {"source": "header:CF-RAY"}
    if "X-Cache" in headers and "HIT" in headers.get("X-Cache", ""):
        techs["CDN (cached)"] = {"source": "header:X-Cache"}
    return techs


def fingerprint(url, client=None):
    """Full tech fingerprint for a single URL."""
    client = client or HTTPClient(timeout=10)
    resp = client.get(url)
    if not resp:
        return {}

    techs = {}
    techs.update(detect_from_headers(resp.headers))
    techs.update(detect_from_body(resp.text))
    techs.update(detect_from_cookies(resp.cookies))
    techs.update(detect_from_response_headers(resp.headers))
    return techs


def fingerprint_multiple(urls, verbose=True):
    """Fingerprint multiple URLs. Returns {url: {tech: info}}."""
    client = HTTPClient(rate_limit=0.3, timeout=10)
    results = {}

    for url in urls:
        if verbose:
            print(f"  [{url}] scanning...", end=" ", flush=True)
        techs = fingerprint(url, client)
        results[url] = techs
        if verbose:
            tech_names = ", ".join(techs.keys()) if techs else "nothing detected"
            print(tech_names)

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tech_detect.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    if not url.startswith("http"):
        url = f"https://{url}"
    print(f"\n[*] Fingerprinting: {url}\n")
    techs = fingerprint(url)
    for name, info in techs.items():
        print(f"  {name}: {info}")
