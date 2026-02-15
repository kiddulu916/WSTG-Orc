# wstg_orchestrator/utils/scope_checker.py
import fnmatch
from urllib.parse import urlparse

class OutOfScopeError(Exception):
    pass


class ScopeChecker:
    def __init__(
        self,
        base_domain: str,
        out_of_scope_urls: list[str] | None = None,
        out_of_scope_ips: list[str] | None = None,
        out_of_scope_attack_vectors: list[str] | None = None,
    ):
        self.base_domain = base_domain.lower()
        self.out_of_scope_urls = [u.lower() for u in (out_of_scope_urls or [])]
        self.out_of_scope_ips = set(out_of_scope_ips or [])
        self.out_of_scope_attack_vectors = set(
            v.lower() for v in (out_of_scope_attack_vectors or [])
        )

    def is_in_scope(self, target: str) -> bool:
        target_lower = target.lower()
        parsed = urlparse(
            target_lower if "http://" or "https://" in target_lower else str(target_lower)
            )
        hostname = parsed.hostname or target_lower

        # Check if IP is blacklisted
        if hostname in self.out_of_scope_ips:
            return False


        # Check blacklist (exact and wildcard)
        for oos in self.out_of_scope_urls:
            if fnmatch.fnmatch(hostname, oos):
                return False
            if hostname == oos:
                return False

        return True

    def is_attack_vector_allowed(self, vector: str) -> bool:
        return vector.lower() not in self.out_of_scope_attack_vectors