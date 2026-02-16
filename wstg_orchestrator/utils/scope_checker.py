# wstg_orchestrator/utils/scope_checker.py
import fnmatch
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    pass


class ScopeChecker:
    def __init__(
        self,
        base_domain: str,
        wildcard_urls: list[str] | None = None,
        in_scope_urls: list[str] | None = None,
        out_of_scope_urls: list[str] | None = None,
        out_of_scope_ips: list[str] | None = None,
        out_of_scope_attack_vectors: list[str] | None = None,
    ):
        self.base_domain = base_domain.lower()
        self.wildcard_urls = [u.lower() for u in (wildcard_urls or [])]
        self.out_of_scope_urls = [u.lower() for u in (out_of_scope_urls or [])]
        self.out_of_scope_ips = set(out_of_scope_ips or [])
        self.out_of_scope_attack_vectors = set(
            v.lower() for v in (out_of_scope_attack_vectors or [])
        )
        # Extract hostnames from in_scope_urls for positive scope matching
        self._in_scope_hostnames = set()
        for url in (in_scope_urls or []):
            url_lower = url.lower()
            if "://" in url_lower:
                parsed = urlparse(url_lower)
                hostname = parsed.hostname or ""
            else:
                hostname = url_lower.split("/")[0].split(":")[0]
            if hostname:
                self._in_scope_hostnames.add(hostname)

    def add_in_scope_hostnames(self, hostnames: list[str]):
        """Dynamically add hostnames to the in-scope set at runtime."""
        for h in hostnames:
            self._in_scope_hostnames.add(h.lower())

    def is_in_scope(self, target: str) -> bool:
        target_lower = target.lower()
        if "://" not in target_lower:
            target_lower = "https://" + target_lower
        parsed = urlparse(target_lower)
        hostname = parsed.hostname or target_lower
        path = parsed.path or ""

        # Check if IP is blacklisted
        if hostname in self.out_of_scope_ips:
            return False

        # Check out-of-scope patterns (deny takes priority)
        if self._matches_out_of_scope(hostname, path):
            return False

        # Check positive scope: base_domain
        if self.base_domain:
            if hostname == self.base_domain or hostname.endswith("." + self.base_domain):
                return True

        # Check positive scope: wildcard_urls (domain + all subdomains)
        for wc_domain in self.wildcard_urls:
            if hostname == wc_domain or hostname.endswith("." + wc_domain):
                return True

        # Check positive scope: in_scope_urls hostnames (exact match)
        if hostname in self._in_scope_hostnames:
            return True

        return False

    def _matches_out_of_scope(self, hostname: str, path: str) -> bool:
        """Check against three out-of-scope pattern types."""
        for pattern in self.out_of_scope_urls:
            # Type 3: Path component wildcard - */segment/*
            if pattern.startswith("*/"):
                segment = pattern
                if segment.startswith("*/"):
                    segment = segment[2:]
                if segment.endswith("/*"):
                    segment = segment[:-2]
                if segment and f"/{segment}/" in path:
                    return True
                if segment and path.rstrip("/").endswith(f"/{segment}"):
                    return True
                continue

            # Type 1: Domain wildcard - *.something.com
            if pattern.startswith("*."):
                domain_part = pattern[2:]
                if hostname == domain_part or hostname.endswith("." + domain_part):
                    return True
                continue

            # Type 2: Domain + path prefix - example.com/path
            if "/" in pattern:
                pattern_host = pattern.split("/")[0]
                pattern_path = "/" + "/".join(pattern.split("/")[1:])
                if fnmatch.fnmatch(hostname, pattern_host) and path.startswith(pattern_path):
                    return True
                continue

            # Simple domain match (exact or fnmatch)
            if fnmatch.fnmatch(hostname, pattern):
                return True

        return False

    def is_attack_vector_allowed(self, vector: str) -> bool:
        return vector.lower() not in self.out_of_scope_attack_vectors
