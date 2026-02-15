# wstg_orchestrator/utils/config_loader.py
import yaml
from urllib.parse import urlparse
from wstg_orchestrator.utils.scope_checker import ScopeChecker


class ConfigLoader:
    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            self._raw = yaml.safe_load(f)
        self._scope = self._raw.get("program_scope", {})
        self._auth = self._raw.get("auth_profiles", {})
        self._tools = self._raw.get("tool_configs", {})
        self._callback = self._raw.get("callback_server", {})

    @property
    def company_name(self) -> str:
        return self._scope.get("company_name", "")

    @property
    def base_domain(self) -> str:
        return self._scope.get("base_domain", "")

    @property
    def rate_limit(self) -> int:
        return self._scope.get("rate_limit", 10)

    @property
    def custom_headers(self) -> dict:
        return self._scope.get("custom_headers", {})

    @property
    def wildcard_urls(self) -> list:
        return self._scope.get("wildcard_urls", [])

    @property
    def wildcard_domains(self) -> list[str]:
        """Strip '*.' prefix from wildcard URLs for use with subdomain enumeration tools."""
        domains = []
        for url in self.wildcard_urls:
            domain = url.lstrip("*.")
            if domain:
                domains.append(domain)
        return list(dict.fromkeys(domains))

    @property
    def enumeration_domains(self) -> list[str]:
        """Return all domains that should be enumerated for subdomains.

        Combines base_domain, wildcard domains (with '*.' stripped),
        and hostnames extracted from in_scope_urls. Deduplicated, order preserved.
        """
        domains = []
        # Always include base domain first
        if self.base_domain:
            domains.append(self.base_domain)
        # Add wildcard domains
        domains.extend(self.wildcard_domains)
        # Extract hostnames from in-scope URLs
        for url in self.in_scope_urls:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            hostname = parsed.hostname
            if hostname:
                domains.append(hostname)
        return list(dict.fromkeys(domains))

    @property
    def in_scope_urls(self) -> list:
        return self._scope.get("in_scope_urls", [])

    @property
    def in_scope_ips(self) -> list:
        return self._scope.get("in_scope_ips", [])

    @property
    def out_of_scope_urls(self) -> list:
        return self._scope.get("out_of_scope_urls", [])

    @property
    def out_of_scope_ips(self) -> list:
        return self._scope.get("out_of_scope_ips", [])

    @property
    def out_of_scope_attack_vectors(self) -> list:
        return self._scope.get("out_of_scope_attack_vectors", [])

    @property
    def notes(self) -> str:
        return self._scope.get("notes", "")

    @property
    def callback_host(self) -> str:
        return self._callback.get("host", "0.0.0.0")

    @property
    def callback_port(self) -> int:
        return self._callback.get("port", 8443)

    def get_tool_config(self, tool_name: str) -> dict:
        return self._tools.get(tool_name, {})

    def get_auth_profile(self, profile_name: str) -> dict | None:
        return self._auth.get(profile_name)

    def create_scope_checker(self) -> ScopeChecker:
        return ScopeChecker(
            base_domain=self.base_domain,
            out_of_scope_urls=self.out_of_scope_urls,
            out_of_scope_ips=self.out_of_scope_ips,
            out_of_scope_attack_vectors=self.out_of_scope_attack_vectors,
        )

    def save(self, path: str):
        with open(path, "w") as f:
            yaml.dump(self._raw, f, default_flow_style=False, sort_keys=False)