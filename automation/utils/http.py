"""
Rate-limited HTTP client with UA rotation, exponential backoff + jitter, proxy/TOR support,
per-mode rate limiting, cookie/header injection. All scanners use this instead of raw requests.
"""

import os
import random
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]

# Named rate profiles
RATE_PROFILES = {
    "stealth":    {"rate_limit": 2.0, "jitter": 1.0, "max_workers": 1, "rotate_ua_every": 1},
    "standard":   {"rate_limit": 0.5, "jitter": 0.3, "max_workers": 10, "rotate_ua_every": 10},
    "aggressive": {"rate_limit": 0.0, "jitter": 0.0, "max_workers": 30, "rotate_ua_every": 50},
}


class HTTPClient:
    def __init__(
        self,
        rate_limit=0.5,
        timeout=15,
        retries=3,
        max_workers=10,
        mode=None,
        proxy=None,
        proxy_list=None,
        cookies=None,
        headers=None,
        verify=False,
        user_agent=None,
        jitter=0.2,
    ):
        self.session = requests.Session()
        if mode and mode in RATE_PROFILES:
            prof = RATE_PROFILES[mode]
            rate_limit = prof["rate_limit"]
            jitter = prof["jitter"]
            max_workers = prof["max_workers"]
            self._rotate_every = prof["rotate_ua_every"]
        else:
            self._rotate_every = 10

        self.rate_limit = rate_limit
        self.jitter = jitter
        self.timeout = timeout
        self.retries = retries
        self.max_workers = max_workers
        self.verify = verify
        self.last_request = 0
        self._counter = 0
        self._current_ua = user_agent or random.choice(USER_AGENTS)
        self._fixed_ua = bool(user_agent)

        # proxy setup
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.proxy_list = proxy_list

        # cookies
        if cookies:
            self.set_cookies(cookies)

        # default headers
        if headers:
            self.session.headers.update(headers)

    def set_cookies(self, cookies):
        """Accept 'a=b; c=d' string or dict."""
        if isinstance(cookies, str):
            for part in cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())
        elif isinstance(cookies, dict):
            for k, v in cookies.items():
                self.session.cookies.set(k, v)

    def set_header(self, key, value):
        self.session.headers[key] = value

    def _pick_proxy(self):
        if self.proxy_list:
            p = random.choice(self.proxy_list)
            return {"http": p, "https": p}
        return None

    def _wait(self):
        elapsed = time.time() - self.last_request
        rl = self.rate_limit + random.uniform(0, self.jitter) if self.jitter else self.rate_limit
        if elapsed < rl:
            time.sleep(rl - elapsed)
        self.last_request = time.time()

    def _headers(self, extra=None):
        self._counter += 1
        if not self._fixed_ua and self._counter % max(1, self._rotate_every) == 0:
            self._current_ua = random.choice(USER_AGENTS)
        h = {"User-Agent": self._current_ua, "Accept": "*/*"}
        if extra:
            h.update(extra)
        return h

    def _request(self, method, url, **kwargs):
        self._wait()
        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                proxies = kwargs.pop("proxies", None) or self._pick_proxy()
                return self.session.request(
                    method,
                    url,
                    headers=self._headers(kwargs.pop("headers", None)),
                    timeout=kwargs.pop("timeout", self.timeout),
                    verify=kwargs.pop("verify", self.verify),
                    proxies=proxies,
                    **kwargs,
                )
            except requests.RequestException as e:
                last_exc = e
                if attempt == self.retries:
                    return None
                # exponential backoff with jitter
                delay = min(30, (2 ** attempt) * 0.5) + random.uniform(0, 0.5)
                time.sleep(delay)
        return None

    def get(self, url, headers=None, allow_redirects=True, verify=None, **kw):
        return self._request(
            "GET", url,
            headers=headers,
            allow_redirects=allow_redirects,
            verify=self.verify if verify is None else verify,
            **kw,
        )

    def head(self, url, headers=None, allow_redirects=True, verify=None, **kw):
        return self._request(
            "HEAD", url,
            headers=headers,
            allow_redirects=allow_redirects,
            verify=self.verify if verify is None else verify,
            **kw,
        )

    def post(self, url, data=None, json=None, headers=None, verify=None, **kw):
        return self._request(
            "POST", url,
            data=data, json=json,
            headers=headers,
            verify=self.verify if verify is None else verify,
            **kw,
        )

    def put(self, url, data=None, json=None, headers=None, verify=None, **kw):
        return self._request(
            "PUT", url,
            data=data, json=json,
            headers=headers,
            verify=self.verify if verify is None else verify,
            **kw,
        )

    def delete(self, url, headers=None, verify=None, **kw):
        return self._request(
            "DELETE", url,
            headers=headers,
            verify=self.verify if verify is None else verify,
            **kw,
        )

    def options(self, url, headers=None, verify=None, **kw):
        return self._request(
            "OPTIONS", url,
            headers=headers,
            verify=self.verify if verify is None else verify,
            **kw,
        )

    def custom(self, method, url, **kw):
        return self._request(method.upper(), url, **kw)

    def bulk_get(self, urls, callback=None):
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {pool.submit(self.get, url): url for url in urls}
            for future in as_completed(future_map):
                url = future_map[future]
                try:
                    resp = future.result()
                    results[url] = resp
                    if callback:
                        callback(url, resp)
                except Exception:
                    results[url] = None
        return results


def client_from_env(mode=None):
    """Construct a client with settings from environment variables."""
    return HTTPClient(
        mode=mode or os.environ.get("BB_MODE", "standard"),
        proxy=os.environ.get("BB_PROXY"),
        cookies=os.environ.get("BB_COOKIES"),
    )
