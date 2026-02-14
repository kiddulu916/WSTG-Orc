# wstg_orchestrator/modules/auth_testing.py
import time
import statistics

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.parser_utils import diff_responses


class AuthTestingModule(BaseModule):
    PHASE_NAME = "auth_testing"
    SUBCATEGORIES = ["username_enumeration", "default_credentials", "lockout_testing"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    DEFAULT_CREDENTIALS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
        ("admin", "12345"), ("root", "root"), ("root", "toor"),
        ("root", "password"), ("test", "test"), ("user", "user"),
        ("guest", "guest"), ("admin", "changeme"), ("admin", ""),
        ("administrator", "administrator"), ("admin", "P@ssw0rd"),
    ]

    async def execute(self):
        if not self.should_skip_subcategory("username_enumeration"):
            await self._username_enumeration()
            self.mark_subcategory_complete("username_enumeration")

        if not self.should_skip_subcategory("default_credentials"):
            await self._default_credentials()
            self.mark_subcategory_complete("default_credentials")

        if not self.should_skip_subcategory("lockout_testing"):
            if self.is_attack_allowed("brute_force"):
                await self._lockout_testing()
            else:
                self.logger.info("Brute force testing not allowed by scope, skipping lockout test")
            self.mark_subcategory_complete("lockout_testing")

    async def _username_enumeration(self):
        self.logger.info("Starting username enumeration")
        auth_endpoints = self.state.get("auth_endpoints") or []
        if not auth_endpoints:
            auth_endpoints = await self._discover_auth_endpoints()

        for endpoint in auth_endpoints:
            # Response difference detection
            try:
                resp_likely_valid = self._post_login(endpoint, "admin", "wrong_password_xyz")
                resp_likely_invalid = self._post_login(endpoint, "definitely_not_a_real_user_xyzzy", "wrong")
                result = self._detect_enum_by_diff(resp_likely_valid, resp_likely_invalid)

                if result["enumerable"]:
                    self.evidence.log_potential_exploit("auth_testing", {
                        "type": "username_enumeration",
                        "url": endpoint,
                        "method": result["method"],
                        "severity": "medium",
                        "description": f"Username enumeration possible via {result['method']}",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "username_enumeration",
                        "url": endpoint,
                        "severity": "medium",
                        "description": f"Username enumeration via {result['method']}",
                    }])
            except Exception as e:
                self.logger.debug(f"Username enum test failed for {endpoint}: {e}")

            # Timing-based detection
            try:
                timings_valid = []
                timings_invalid = []
                for _ in range(5):
                    start = time.monotonic()
                    self._post_login(endpoint, "admin", "wrong")
                    timings_valid.append(time.monotonic() - start)

                    start = time.monotonic()
                    self._post_login(endpoint, "nonexistent_user_xyzzy", "wrong")
                    timings_invalid.append(time.monotonic() - start)

                avg_valid = statistics.mean(timings_valid)
                avg_invalid = statistics.mean(timings_invalid)
                if abs(avg_valid - avg_invalid) > 0.3:
                    self.evidence.log_potential_exploit("auth_testing", {
                        "type": "username_enumeration_timing",
                        "url": endpoint,
                        "avg_valid_user_time": avg_valid,
                        "avg_invalid_user_time": avg_invalid,
                        "severity": "medium",
                    })
            except Exception:
                pass

    async def _discover_auth_endpoints(self) -> list[str]:
        live_hosts = self.state.get("live_hosts") or []
        endpoints = self.state.get("endpoints") or []
        auth_paths = ["/login", "/signin", "/auth", "/api/login", "/api/auth",
                      "/account/login", "/user/login", "/admin/login"]
        found = []
        for host in live_hosts:
            base = host.rstrip("/")
            for path in auth_paths:
                try:
                    resp = self._http_get(f"{base}{path}")
                    if resp.status_code in [200, 302, 401, 405]:
                        found.append(f"{base}{path}")
                except Exception:
                    continue
        if found:
            self.state.enrich("auth_endpoints", found)
        return found

    def _detect_enum_by_diff(self, resp_valid_user, resp_invalid_user) -> dict:
        # Response content diff
        diff = diff_responses(resp_valid_user.text, resp_invalid_user.text)
        if not diff["identical"] and diff["similarity"] < 0.95:
            return {"enumerable": True, "method": "response_content"}

        # Status code diff
        if resp_valid_user.status_code != resp_invalid_user.status_code:
            return {"enumerable": True, "method": "status_code"}

        # Response length diff
        if abs(diff["length_diff"]) > 10:
            return {"enumerable": True, "method": "response_length"}

        return {"enumerable": False, "method": None}

    async def _default_credentials(self):
        self.logger.info("Starting default credential testing")
        auth_endpoints = self.state.get("auth_endpoints") or []

        for endpoint in auth_endpoints:
            for username, password in self.DEFAULT_CREDENTIALS:
                try:
                    resp = self._post_login(endpoint, username, password)
                    if self._is_login_success(resp):
                        self.logger.critical(
                            f"DEFAULT CREDENTIALS FOUND: {username}:{password} at {endpoint}"
                        )
                        self.evidence.log_confirmed_exploit("auth_testing", {
                            "type": "default_credentials",
                            "url": endpoint,
                            "username": username,
                            "password": password,
                            "severity": "critical",
                            "description": f"Default credentials {username}:{password} accepted",
                        })
                        self.state.enrich("confirmed_vulnerabilities", [{
                            "type": "default_credentials",
                            "url": endpoint,
                            "severity": "critical",
                            "description": f"Default credentials {username}:{password} accepted",
                            "reproduction_steps": f"1. Navigate to {endpoint}\n2. Enter username: {username}\n3. Enter password: {password}\n4. Submit login form",
                            "impact": "Full account access with default credentials",
                            "mitigation": "Force password change on first login. Remove default accounts.",
                        }])
                        self.state.enrich("valid_usernames", [username])
                        return  # Stop after first success
                except Exception:
                    continue

    async def _lockout_testing(self):
        self.logger.info("Starting lockout testing")
        auth_endpoints = self.state.get("auth_endpoints") or []

        for endpoint in auth_endpoints:
            lockout_detected = False
            captcha_detected = False
            attempts_before_lockout = 0

            for i in range(20):  # Test up to 20 attempts
                try:
                    resp = self._post_login(endpoint, "admin", f"wrong_password_{i}")
                    body_lower = resp.text.lower()

                    if "locked" in body_lower or "too many" in body_lower or resp.status_code == 429:
                        lockout_detected = True
                        attempts_before_lockout = i + 1
                        break
                    if "captcha" in body_lower or "recaptcha" in body_lower:
                        captcha_detected = True
                        attempts_before_lockout = i + 1
                        break
                except Exception:
                    break

            finding = {
                "url": endpoint,
                "lockout_detected": lockout_detected,
                "captcha_detected": captcha_detected,
                "attempts_before_trigger": attempts_before_lockout,
            }

            if not lockout_detected and not captcha_detected:
                finding["type"] = "weak_lockout"
                finding["description"] = "No account lockout or rate limiting detected after 20 failed attempts"
                self.state.enrich("potential_vulnerabilities", [finding])
                self.evidence.log_potential_exploit("auth_testing", finding)
            else:
                self.evidence.log_parsed("auth_testing", "lockout_results", finding)

    def _post_login(self, url: str, username: str, password: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data={"username": username, "password": password})

    def _http_get(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    def _is_login_success(self, resp) -> bool:
        if resp.status_code in [302, 303] and "location" in {k.lower() for k in resp.headers}:
            location = resp.headers.get("Location", resp.headers.get("location", ""))
            if "dashboard" in location or "home" in location or "welcome" in location:
                return True
        if resp.status_code == 200:
            body_lower = resp.text.lower()
            success_indicators = ["welcome", "dashboard", "logout", "my account", "profile"]
            failure_indicators = ["invalid", "incorrect", "failed", "error", "wrong"]
            if any(s in body_lower for s in success_indicators) and \
               not any(f in body_lower for f in failure_indicators):
                return True
        return False