# wstg_orchestrator/utils/config_loader.py
import yaml
from wstg_orchestrator.utils.scope_checker import ScopeChecker


class ConfigLoader:
    def __init__(self, config_path: str):
        self.config_path = config_path
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
    def enumeration_domains(self) -> list[str]:
        """
        Return all domains that should be enumerated for subdomains.
        Combines base_domain and wildcard_urls only. in_scope_urls are excluded.
        Deduplicated, order preserved.
        """
        domains = []
        if self.base_domain:
            domains.append(self.base_domain)
        domains.extend(self.wildcard_urls)
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
    def auto_expand_scope(self) -> bool:
        return self._scope.get("auto_expand_scope", True)

    @property
    def callback_host(self) -> str:
        return self._callback.get("host", "0.0.0.0")

    @property
    def callback_port(self) -> int:
        return self._callback.get("port", 8443)

    def get_tool_config(self, tool_name: str) -> dict:
        return self._tools.get(tool_name, {})

    def update_tool_config(self, tool_name: str, key: str, value):
        """Update a single key in a tool's config, persisting to YAML on disk."""
        if tool_name not in self._tools:
            self._tools[tool_name] = {}
        self._tools[tool_name][key] = value
        self._raw.setdefault("tool_configs", {})[tool_name] = self._tools[tool_name]
        self.save(self.config_path)

    def get_auth_profile(self, profile_name: str) -> dict | None:
        return self._auth.get(profile_name)

    def create_scope_checker(self) -> ScopeChecker:
        return ScopeChecker(
            base_domain=self.base_domain,
            wildcard_urls=self.wildcard_urls,
            in_scope_urls=self.in_scope_urls,
            out_of_scope_urls=self.out_of_scope_urls,
            out_of_scope_ips=self.out_of_scope_ips,
            out_of_scope_attack_vectors=self.out_of_scope_attack_vectors,
        )

    def save(self, path: str):
        with open(path, "w") as f:
            yaml.dump(self._raw, f, default_flow_style=False, sort_keys=False)

    def append_in_scope_urls(self, urls: list[str]):
        """Append URLs to in_scope_urls in both memory and YAML on disk.

        Deduplicates against existing entries. Writes to self.config_path.
        """
        if not urls:
            return
        current = self._scope.get("in_scope_urls", [])
        new_urls = [u for u in urls if u not in current]
        if not new_urls:
            return
        current.extend(new_urls)
        self._scope["in_scope_urls"] = current
        self._raw.setdefault("program_scope", {})["in_scope_urls"] = current
        self.save(self.config_path)