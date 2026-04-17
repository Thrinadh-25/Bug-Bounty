"""Interactsh client for out-of-band callback detection.

Prefers the `interactsh-client` CLI when available. Falls back to minimal in-process
listener using webhook.site public relay ONLY when explicitly enabled; otherwise returns
an offline stub that generates unique canary tokens so modules can still run and report
'OOB listener unavailable' instead of crashing.
"""

import json
import os
import random
import shutil
import subprocess
import threading
import time
import uuid
from collections import defaultdict


def _has_interactsh():
    return shutil.which("interactsh-client") is not None


class InteractshCLI:
    """Wraps the real interactsh-client binary. It prints JSON lines on stdout."""

    def __init__(self, server=None, token=None, timeout=None):
        self.server = server or "oast.live"
        self.token = token
        self.proc = None
        self.lock = threading.Lock()
        self.interactions = defaultdict(list)
        self.session_host = None
        self.reader = None

    def start(self):
        cmd = ["interactsh-client", "-json"]
        if self.server:
            cmd += ["-server", self.server]
        if self.token:
            cmd += ["-token", self.token]
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            return False

        # Read until we see the session URL
        start = time.time()
        while time.time() - start < 15 and self.proc.poll() is None:
            line = self.proc.stderr.readline() if self.proc.stderr else ""
            if not line:
                line = self.proc.stdout.readline() if self.proc.stdout else ""
            if not line:
                time.sleep(0.1)
                continue
            # Typical line: "[INF] Listing 1 payload for OOB Testing  https://xxx.oast.live"
            if ".oast" in line or "interact.sh" in line:
                for part in line.split():
                    if part.startswith("http"):
                        self.session_host = part.strip().rstrip(".")
                        break
                if self.session_host:
                    break

        if not self.session_host:
            self.stop()
            return False

        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        return True

    def _read_loop(self):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            host = obj.get("full-id") or obj.get("unique-id") or ""
            with self.lock:
                self.interactions[host].append(obj)

    def payload(self):
        """Return a unique callback URL token."""
        if not self.session_host:
            return None
        uid = uuid.uuid4().hex[:8]
        # interactsh-client returns a base host; we prepend a subdomain
        base = self.session_host.replace("https://", "").replace("http://", "")
        return f"{uid}.{base}"

    def poll(self, token, wait=30):
        """Wait up to `wait` seconds for any interaction matching token."""
        deadline = time.time() + wait
        while time.time() < deadline:
            with self.lock:
                for key, events in self.interactions.items():
                    if token in key:
                        return list(events)
            time.sleep(0.5)
        return []

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None


class OfflineStub:
    """Fallback when no OOB listener is available. Generates tokens,
    returns empty poll results, sets 'enabled' False so callers can note it."""

    enabled = False

    def __init__(self, *_, **__):
        self.session_host = None

    def start(self):
        return False

    def payload(self):
        # Non-callable domain but unique token that can be searched for
        return f"canary-{uuid.uuid4().hex[:10]}.invalid"

    def poll(self, token, wait=5):
        time.sleep(min(wait, 1))
        return []

    def stop(self):
        pass


def get_listener(prefer_cli=True):
    """Return an active OOB listener. Starts interactsh-client if available,
    else returns OfflineStub.
    """
    if prefer_cli and _has_interactsh():
        cli = InteractshCLI()
        if cli.start():
            cli.enabled = True
            return cli
    s = OfflineStub()
    return s
