"""OPSEC layer — controls rate, UA rotation, proxy/TOR routing, and tool signature obfuscation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.http import HTTPClient, RATE_PROFILES


TOR_SOCKS = "socks5h://127.0.0.1:9050"


class OpSec:
    def __init__(self, mode="standard", proxy=None, proxy_list=None, use_tor=False):
        assert mode in RATE_PROFILES, f"mode must be one of {list(RATE_PROFILES)}"
        self.mode = mode
        self.proxy = proxy
        self.proxy_list = proxy_list or []
        self.use_tor = use_tor
        if use_tor:
            self.proxy = TOR_SOCKS

    def new_client(self, cookies=None, headers=None):
        return HTTPClient(
            mode=self.mode,
            proxy=self.proxy,
            proxy_list=self.proxy_list,
            cookies=cookies,
            headers=headers,
        )

    def tool_args(self, tool):
        """Return additional CLI args that customize a tool's signature to avoid trivial detection."""
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        )
        if tool == "sqlmap":
            args = ["--random-agent", "--user-agent", ua]
            if self.mode == "stealth":
                args += ["--delay", "2", "--timeout", "30", "--randomize", "id"]
            elif self.mode == "aggressive":
                args += ["--threads", "10"]
            return args
        if tool == "nuclei":
            args = ["-H", f"User-Agent: {ua}"]
            if self.mode == "stealth":
                args += ["-rl", "30", "-c", "5"]
            elif self.mode == "aggressive":
                args += ["-rl", "500", "-c", "50"]
            return args
        if tool == "dalfox":
            args = ["--user-agent", ua]
            if self.mode == "stealth":
                args += ["--delay", "1500"]
            return args
        if tool == "ffuf":
            args = ["-H", f"User-Agent: {ua}"]
            if self.mode == "stealth":
                args += ["-rate", "20"]
            elif self.mode == "aggressive":
                args += ["-rate", "0", "-t", "100"]
            return args
        return []

    def subprocess_env(self):
        env = os.environ.copy()
        if self.proxy:
            env["HTTPS_PROXY"] = self.proxy
            env["HTTP_PROXY"] = self.proxy
        return env
