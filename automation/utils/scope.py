"""
Scope enforcement — NEVER touch anything outside scope.
Every scanner checks this before making requests.
"""

import re
from urllib.parse import urlparse


class ScopeChecker:
    def __init__(self):
        self.in_scope_domains = []
        self.out_of_scope_domains = []
        self.out_of_scope_paths = []
        self.rules = []

    def load_from_file(self, filepath):
        section = None
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower() == "[in-scope]":
                    section = "in"
                elif line.lower() == "[out-of-scope]":
                    section = "out"
                elif line.lower() == "[rules]":
                    section = "rules"
                elif section == "in":
                    self.in_scope_domains.append(line.lower())
                elif section == "out":
                    self.out_of_scope_domains.append(line.lower())
                elif section == "rules":
                    self.rules.append(line.lower())

    def add_target(self, domain):
        domain = domain.lower().strip()
        if domain not in self.in_scope_domains:
            self.in_scope_domains.append(domain)
            self.in_scope_domains.append(f"*.{domain}")

    def add_exclusion(self, domain):
        domain = domain.lower().strip()
        if domain not in self.out_of_scope_domains:
            self.out_of_scope_domains.append(domain)

    def _domain_from_input(self, target):
        target = target.lower().strip()
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or ""
        return target.split("/")[0].split(":")[0]

    def _matches_pattern(self, domain, pattern):
        pattern = pattern.lower()
        domain = domain.lower()
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain == base or domain.endswith(f".{base}")
        return domain == pattern

    def is_in_scope(self, target):
        domain = self._domain_from_input(target)
        if not domain:
            return False

        for pattern in self.out_of_scope_domains:
            if self._matches_pattern(domain, pattern):
                return False

        for pattern in self.in_scope_domains:
            if self._matches_pattern(domain, pattern):
                return True

        return False

    def enforce(self, target):
        if not self.is_in_scope(target):
            raise ScopeViolation(f"OUT OF SCOPE: {target}")
        return True

    def filter_targets(self, targets):
        return [t for t in targets if self.is_in_scope(t)]

    def summary(self):
        lines = ["=== SCOPE ==="]
        lines.append(f"In-scope: {', '.join(self.in_scope_domains)}")
        if self.out_of_scope_domains:
            lines.append(f"Out-of-scope: {', '.join(self.out_of_scope_domains)}")
        if self.rules:
            lines.append(f"Rules: {', '.join(self.rules)}")
        return "\n".join(lines)


class ScopeViolation(Exception):
    pass
