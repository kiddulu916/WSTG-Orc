# wstg_orchestrator/scope_builder.py
import yaml


class ScopeBuilder:
    def build(self) -> dict:
        print("\n=== WSTG Orchestrator - Scope Builder ===\n")

        company_name = input("Company name: ").strip()
        base_domain = input("Base domain (e.g., example.com): ").strip()

        in_scope_urls = self._parse_list(
            input("In-scope URLs (comma-separated, or empty): ")
        )
        in_scope_ips = self._parse_list(
            input("In-scope IPs (comma-separated, or empty): ")
        )
        out_of_scope_urls = self._parse_list(
            input("Out-of-scope URLs (comma-separated, or empty): ")
        )
        out_of_scope_ips = self._parse_list(
            input("Out-of-scope IPs (comma-separated, or empty): ")
        )
        out_of_scope_attack_vectors = self._parse_list(
            input("Out-of-scope attack vectors (e.g., dos, social_engineering): ")
        )

        rate_limit_raw = input("Rate limit (requests/sec, default 10): ").strip()
        rate_limit = int(rate_limit_raw) if rate_limit_raw else 10

        headers_raw = input("Custom headers (Key: Value, comma-separated, or empty): ").strip()
        custom_headers = self._parse_headers(headers_raw)

        auth_raw = input("Auth profile (type:credential, or empty to skip): ").strip()
        auth_profiles = {}
        if auth_raw:
            auth_profiles = self._parse_auth(auth_raw)

        callback_host = input("Callback server host (default 0.0.0.0): ").strip() or "0.0.0.0"
        callback_port_raw = input("Callback server port (default 8443): ").strip()
        callback_port = int(callback_port_raw) if callback_port_raw else 8443

        notes = input("Additional notes: ").strip()

        return {
            "program_scope": {
                "company_name": company_name,
                "base_domain": base_domain,
                "wildcard_urls": [f"*.{base_domain}"],
                "in_scope_urls": in_scope_urls,
                "in_scope_ips": in_scope_ips,
                "out_of_scope_urls": out_of_scope_urls,
                "out_of_scope_ips": out_of_scope_ips,
                "out_of_scope_attack_vectors": out_of_scope_attack_vectors,
                "rate_limit": rate_limit,
                "custom_headers": custom_headers,
                "notes": notes,
            },
            "auth_profiles": auth_profiles,
            "tool_configs": {},
            "callback_server": {
                "host": callback_host,
                "port": callback_port,
            },
        }

    def _parse_list(self, raw: str) -> list[str]:
        if not raw.strip():
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _parse_headers(self, raw: str) -> dict:
        if not raw:
            return {}
        headers = {}
        for item in raw.split(","):
            if ":" in item:
                key, value = item.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers

    def _parse_auth(self, raw: str) -> dict:
        if ":" in raw:
            auth_type, credential = raw.split(":", 1)
            return {
                "default": {
                    "type": auth_type.strip(),
                    "token": credential.strip(),
                }
            }
        return {}

    @staticmethod
    def save_config(config: dict, path: str):
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)