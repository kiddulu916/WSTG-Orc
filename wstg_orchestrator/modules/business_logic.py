# wstg_orchestrator/modules/business_logic.py
import concurrent.futures
import time

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.parser_utils import diff_responses


class BusinessLogicModule(BaseModule):
    PHASE_NAME = "business_logic"
    SUBCATEGORIES = ["workflow_bypass", "parameter_tampering", "race_conditions"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    PRICE_TAMPER_VALUES = [0, -1, 0.01, 0.001, 99999999, -99.99]
    QUANTITY_TAMPER_VALUES = [0, -1, 99999999, 0.5]

    async def execute(self):
        if not self.should_skip_subcategory("workflow_bypass"):
            await self._workflow_bypass()
            self.mark_subcategory_complete("workflow_bypass")

        if not self.should_skip_subcategory("parameter_tampering"):
            await self._parameter_tampering()
            self.mark_subcategory_complete("parameter_tampering")

        if not self.should_skip_subcategory("race_conditions"):
            if self.is_attack_allowed("dos"):
                await self._race_conditions()
            else:
                self.logger.info("DoS-style testing blocked by scope, skipping race conditions")
            self.mark_subcategory_complete("race_conditions")

    async def _workflow_bypass(self):
        self.logger.info("Starting workflow bypass testing")
        endpoints = self.state.get("endpoints") or []

        # Identify multi-step workflows
        checkout_patterns = [
            "/checkout", "/payment", "/confirm", "/review",
            "/step2", "/step3", "/finalize", "/complete",
        ]

        workflow_endpoints = [
            ep for ep in endpoints
            if any(p in ep.lower() for p in checkout_patterns)
        ]

        # Try accessing later steps directly without completing earlier ones
        for endpoint in workflow_endpoints:
            try:
                resp = self._http_get(endpoint)
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    # Check if we got the actual page instead of a redirect
                    if not any(err in body_lower for err in ["redirect", "login", "unauthorized", "forbidden"]):
                        self.evidence.log_potential_exploit("business_logic", {
                            "type": "workflow_bypass",
                            "url": endpoint,
                            "severity": "medium",
                            "description": f"Direct access to workflow step without completing prerequisites",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "workflow_bypass",
                            "url": endpoint,
                            "severity": "medium",
                            "description": "Workflow step accessible without completing prior steps",
                        }])
            except Exception:
                continue

    async def _parameter_tampering(self):
        self.logger.info("Starting parameter tampering")
        parameters = self.state.get("parameters") or []

        # Price tampering
        price_params = [p for p in parameters if p.get("name", "").lower() in
                        ["price", "amount", "total", "cost", "fee", "charge", "subtotal"]]

        for param in price_params:
            url = param["url"]
            name = param["name"]
            for tamper_value in self.PRICE_TAMPER_VALUES:
                try:
                    resp = self._http_post(url, data={name: str(tamper_value)})
                    if resp.status_code == 200:
                        self.evidence.log_potential_exploit("business_logic", {
                            "type": "price_tampering",
                            "url": url, "parameter": name,
                            "original_value": param.get("value"),
                            "tampered_value": tamper_value,
                            "severity": "high",
                            "description": f"Price parameter accepted tampered value: {tamper_value}",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "price_tampering",
                            "url": url,
                            "severity": "high",
                            "description": f"Price param '{name}' accepted value: {tamper_value}",
                        }])
                except Exception:
                    continue

        # Quantity tampering
        qty_params = [p for p in parameters if p.get("name", "").lower() in
                      ["quantity", "qty", "count", "num", "amount"]]

        for param in qty_params:
            url = param["url"]
            name = param["name"]
            for tamper_value in self.QUANTITY_TAMPER_VALUES:
                try:
                    resp = self._http_post(url, data={name: str(tamper_value)})
                    if resp.status_code == 200:
                        self.evidence.log_potential_exploit("business_logic", {
                            "type": "quantity_tampering",
                            "url": url, "parameter": name,
                            "tampered_value": tamper_value,
                            "severity": "medium",
                        })
                except Exception:
                    continue

    async def _race_conditions(self):
        self.logger.info("Starting race condition testing")
        endpoints = self.state.get("endpoints") or []

        # Target endpoints that modify state
        state_changing = [
            ep for ep in endpoints
            if any(p in ep.lower() for p in [
                "/apply", "/redeem", "/coupon", "/transfer",
                "/withdraw", "/buy", "/order", "/vote",
            ])
        ]

        for endpoint in state_changing[:3]:  # Limit to 3
            try:
                responses = self._send_concurrent(endpoint, count=10)
                success_count = sum(1 for r in responses if r and r.status_code == 200)
                unique_bodies = len(set(r.text[:200] for r in responses if r))

                if success_count > 1 and unique_bodies > 1:
                    self.evidence.log_potential_exploit("business_logic", {
                        "type": "race_condition",
                        "url": endpoint,
                        "concurrent_successes": success_count,
                        "unique_responses": unique_bodies,
                        "severity": "high",
                        "description": "Inconsistent state under concurrent requests",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "race_condition",
                        "url": endpoint,
                        "severity": "high",
                        "description": f"Race condition: {success_count}/10 concurrent requests succeeded with {unique_bodies} unique responses",
                    }])
            except Exception as e:
                self.logger.debug(f"Race condition test failed for {endpoint}: {e}")

    def _send_concurrent(self, url: str, count: int = 10):
        from wstg_orchestrator.utils.http_utils import HttpClient
        headers = self.config.custom_headers if hasattr(self.config, 'custom_headers') else {}

        def send_one(_):
            try:
                client = HttpClient(
                    scope_checker=self.scope,
                    rate_limiter=self.rate_limiter,
                    custom_headers=headers,
                )
                return client.try_request(url, method="POST")
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(send_one, i) for i in range(count)]
            return [f.result() for f in concurrent.futures.as_completed(futures)]

    def _http_get(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.try_request(url)

    def _http_post(self, url: str, data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.try_request(url, method="POST", data=data)