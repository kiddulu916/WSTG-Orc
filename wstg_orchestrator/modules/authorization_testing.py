# wstg_orchestrator/modules/authorization_testing.py
import base64
import json
import re

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.parser_utils import diff_responses


class AuthorizationTestingModule(BaseModule):
    PHASE_NAME = "authorization_testing"
    SUBCATEGORIES = ["idor_testing", "privilege_escalation", "jwt_testing"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    async def execute(self):
        if not self.should_skip_subcategory("idor_testing"):
            await self._idor_testing()
            self.mark_subcategory_complete("idor_testing")

        if not self.should_skip_subcategory("privilege_escalation"):
            await self._privilege_escalation()
            self.mark_subcategory_complete("privilege_escalation")

        if not self.should_skip_subcategory("jwt_testing"):
            await self._jwt_testing()
            self.mark_subcategory_complete("jwt_testing")

    async def _idor_testing(self):
        self.logger.info("Starting IDOR testing")
        candidates = self.state.get("potential_idor_candidates") or []

        for candidate in candidates:
            if candidate["type"] == "numeric":
                await self._test_numeric_idor(candidate)
            elif candidate["type"] == "uuid":
                self.logger.info(f"UUID IDOR candidate detected: {candidate['url']} (manual review recommended)")
                self.evidence.log_parsed("authorization_testing", "uuid_idor_candidate", candidate)

    async def _test_numeric_idor(self, candidate: dict):
        url = candidate["url"]
        original_id = candidate["value"]
        test_ids = self._generate_numeric_idor_values(original_id)

        try:
            original_resp = self._http_get(url)
        except Exception:
            return

        for test_id in test_ids:
            test_url = url.replace(f"/{original_id}", f"/{test_id}")
            try:
                test_resp = self._http_get(test_url)
                if test_resp.status_code == 200:
                    diff = diff_responses(original_resp.text, test_resp.text)
                    if not diff["identical"] and diff["similarity"] > 0.3:
                        self.evidence.log_potential_exploit("authorization_testing", {
                            "type": "idor",
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "severity": "high",
                            "response_similarity": diff["similarity"],
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "idor",
                            "url": test_url,
                            "severity": "high",
                            "description": f"Potential IDOR: changing ID from {original_id} to {test_id} returned different data",
                        }])
            except Exception:
                continue

    def _generate_numeric_idor_values(self, original: str) -> list[int]:
        val = int(original)
        candidates = [val - 1, val + 1, val - 2, val + 2, 1, 0]
        return [c for c in candidates if c >= 0 and c != val]

    async def _privilege_escalation(self):
        self.logger.info("Starting privilege escalation testing")
        endpoints = self.state.get("endpoints") or []
        params = self.state.get("parameters") or []

        # Hidden field tampering - look for role/admin parameters
        role_params = [p for p in params if p.get("name", "").lower() in
                       ["role", "admin", "is_admin", "isadmin", "user_role",
                        "privilege", "level", "access_level", "group"]]

        for param in role_params:
            url = param.get("url", "")
            name = param.get("name", "")
            for tamper_value in ["admin", "1", "true", "root", "superadmin"]:
                try:
                    resp = self._http_post(url, data={name: tamper_value})
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        if any(ind in body_lower for ind in ["admin", "dashboard", "manage", "settings"]):
                            self.evidence.log_potential_exploit("authorization_testing", {
                                "type": "privilege_escalation",
                                "url": url,
                                "parameter": name,
                                "tampered_value": tamper_value,
                                "severity": "critical",
                            })
                            self.state.enrich("potential_vulnerabilities", [{
                                "type": "privilege_escalation",
                                "url": url,
                                "severity": "critical",
                                "description": f"Potential privilege escalation via {name}={tamper_value}",
                            }])
                except Exception:
                    continue

    async def _jwt_testing(self):
        self.logger.info("Starting JWT testing")
        # Look for JWTs in responses from auth endpoints
        auth_endpoints = self.state.get("auth_endpoints") or []
        live_hosts = self.state.get("live_hosts") or []

        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        for url in auth_endpoints + live_hosts:
            try:
                resp = self._http_get(url)
                # Check response body and headers for JWTs
                all_text = resp.text + str(resp.headers)
                tokens = jwt_pattern.findall(all_text)

                for token in tokens:
                    decoded = self._decode_jwt(token)
                    if decoded:
                        self.evidence.log_parsed("authorization_testing", "jwt_decoded", {
                            "url": url, "header": decoded["header"],
                            "payload": decoded["payload"],
                        })

                        # Test algorithm=none
                        if decoded["header"].get("alg") != "none":
                            none_token = self._craft_none_jwt(decoded["payload"])
                            try:
                                none_resp = self._http_get(url, extra_headers={
                                    "Authorization": f"Bearer {none_token}"
                                })
                                if none_resp.status_code == 200:
                                    self.evidence.log_confirmed_exploit("authorization_testing", {
                                        "type": "jwt_alg_none",
                                        "url": url,
                                        "severity": "critical",
                                        "description": "JWT accepts algorithm=none, signature validation bypassed",
                                    })
                                    self.state.enrich("confirmed_vulnerabilities", [{
                                        "type": "jwt_alg_none",
                                        "url": url,
                                        "severity": "critical",
                                        "description": "JWT accepts algorithm=none",
                                        "reproduction_steps": "1. Decode JWT\n2. Set header alg to 'none'\n3. Remove signature\n4. Send modified token",
                                        "impact": "Complete authentication bypass",
                                        "mitigation": "Validate JWT algorithm server-side. Reject 'none' algorithm.",
                                    }])
                            except Exception:
                                pass
            except Exception:
                continue

    def _decode_jwt(self, token: str) -> dict | None:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            def decode_part(part: str) -> dict:
                padding = 4 - len(part) % 4
                part += "=" * padding
                decoded = base64.urlsafe_b64decode(part)
                return json.loads(decoded)

            return {
                "header": decode_part(parts[0]),
                "payload": decode_part(parts[1]),
                "signature": parts[2],
            }
        except Exception:
            return None

    def _craft_none_jwt(self, payload: dict) -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        return f"{header}.{payload_b64}."

    def _http_get(self, url: str, extra_headers: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.try_request(url, headers=extra_headers)

    def _http_post(self, url: str, data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.try_request(url, method="POST", data=data)