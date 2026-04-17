"""Session management — accept cookies/headers/creds, support multiple concurrent sessions
(e.g. admin + user for privilege escalation tests), refresh on 401."""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient


class Session:
    def __init__(self, name, cookies=None, headers=None, auth=None, login_url=None, login_data=None):
        self.name = name
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.auth = auth
        self.login_url = login_url
        self.login_data = login_data or {}
        self.last_refresh = time.time()
        self.client = HTTPClient(cookies=self.cookies, headers=self.headers)

    def refresh(self):
        if not self.login_url:
            return False
        resp = self.client.post(self.login_url, data=self.login_data)
        if resp and resp.status_code in (200, 302):
            self.last_refresh = time.time()
            # merge any Set-Cookies
            return True
        return False

    def request(self, method, url, **kw):
        """Make a request with auto-refresh on 401."""
        resp = self.client.custom(method, url, **kw)
        if resp is not None and resp.status_code == 401 and self.login_url:
            self.refresh()
            resp = self.client.custom(method, url, **kw)
        return resp


class SessionManager:
    def __init__(self):
        self.sessions = {}

    @staticmethod
    def _parse_cookies(cookie_str):
        out = {}
        if not cookie_str:
            return out
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _parse_headers_file(path):
        out = {}
        if not path or not os.path.exists(path):
            return out
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
        return out

    def add(self, name, cookies=None, headers=None, headers_file=None, login_url=None, login_data=None):
        if isinstance(cookies, str):
            cookies = self._parse_cookies(cookies)
        hdrs = dict(headers or {})
        if headers_file:
            hdrs.update(self._parse_headers_file(headers_file))
        s = Session(name, cookies=cookies, headers=hdrs, login_url=login_url, login_data=login_data)
        self.sessions[name] = s
        return s

    def get(self, name="default"):
        return self.sessions.get(name)

    def all(self):
        return list(self.sessions.values())

    def has_multi(self):
        return len(self.sessions) >= 2

    def save(self, path):
        data = {}
        for name, s in self.sessions.items():
            data[name] = {
                "cookies": dict(s.client.session.cookies),
                "headers": dict(s.headers),
                "login_url": s.login_url,
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path):
        mgr = cls()
        if not os.path.exists(path):
            return mgr
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for name, cfg in data.items():
            mgr.add(
                name,
                cookies=cfg.get("cookies"),
                headers=cfg.get("headers"),
                login_url=cfg.get("login_url"),
            )
        return mgr
