# wstg_orchestrator/modules/session_testing.py
import re

from wstg_orchestrator.modules.base_module import BaseModule


class SessionTestingModule(BaseModule):
    PHASE_NAME = "session_testing"
    SUBCATEGORIES = ["cookie_flags", "session_fixation", "session_lifecycle"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    async def execute(self):
        if not self.should_skip_subcategory("cookie_flags"):
            await self._cookie_flags()
            self.mark_subcategory_complete("cookie_flags")

        if not self.should_skip_subcategory("session_fixation"):
            await self._session_fixation()
            self.mark_subcategory_complete("session_fixation")

        if not self.should_skip_subcategory("session_lifecycle"):
            await self._session_lifecycle()
            self.mark_subcategory_complete("session_lifecycle")

    async def _cookie_flags(self):
        self.logger.info("Starting cookie flag analysis")
        live_hosts = self.state.get("live_hosts") or []

        for host_url in live_hosts:
            try:
                resp = self._http_get(host_url)
                set_cookies = []
                for key, value in resp.headers.items():
                    if key.lower() == "set-cookie":
                        set_cookies.append(value)

                # Also check if headers is a dict with combined cookies
                if not set_cookies and "Set-Cookie" in resp.headers:
                    set_cookies = [resp.headers["Set-Cookie"]]

                for cookie_str in set_cookies:
                    name_match = re.match(r'([^=]+)=', cookie_str)
                    if not name_match:
                        continue
                    name = name_match.group(1).strip()
                    analysis = self._analyze_cookie_flags(name, cookie_str)
                    analysis["url"] = host_url

                    issues = []
                    if not analysis["httponly"]:
                        issues.append("Missing HttpOnly flag")
                    if not analysis["secure"] and host_url.startswith("https"):
                        issues.append("Missing Secure flag")
                    if analysis["samesite"] is None:
                        issues.append("Missing SameSite attribute")

                    if issues:
                        finding = {
                            "type": "insecure_cookie",
                            "url": host_url,
                            "cookie_name": name,
                            "issues": issues,
                            "severity": "low",
                            "description": f"Cookie '{name}' missing flags: {', '.join(issues)}",
                        }
                        self.state.enrich("potential_vulnerabilities", [finding])
                        self.evidence.log_potential_exploit("session_testing", finding)

                    self.evidence.log_parsed("session_testing", f"cookie_{name}", analysis)
            except Exception as e:
                self.logger.debug(f"Cookie analysis failed for {host_url}: {e}")

    def _analyze_cookie_flags(self, name: str, cookie_str: str) -> dict:
        cookie_lower = cookie_str.lower()
        samesite = None
        samesite_match = re.search(r'samesite=(\w+)', cookie_lower)
        if samesite_match:
            samesite = samesite_match.group(1).capitalize()

        return {
            "name": name,
            "httponly": "httponly" in cookie_lower,
            "secure": "secure" in cookie_lower.split(";")
                      or any("secure" == part.strip() for part in cookie_lower.split(";")),
            "samesite": samesite,
            "path": self._extract_attr(cookie_str, "path"),
            "domain": self._extract_attr(cookie_str, "domain"),
        }

    def _extract_attr(self, cookie_str: str, attr: str) -> str | None:
        match = re.search(rf'{attr}=([^;]+)', cookie_str, re.I)
        return match.group(1).strip() if match else None

    async def _session_fixation(self):
        self.logger.info("Starting session fixation testing")
        auth_endpoints = self.state.get("auth_endpoints") or []

        for endpoint in auth_endpoints:
            try:
                # Get a session cookie before login
                pre_resp = self._http_get(endpoint)
                pre_cookies = self._extract_session_cookies(pre_resp)

                if not pre_cookies:
                    continue

                # Attempt login (with test credentials)
                post_resp = self._http_post(endpoint, data={
                    "username": "test_fixation_check", "password": "test_fixation_check"
                })
                post_cookies = self._extract_session_cookies(post_resp)

                # Check if session ID changed after login attempt
                for cookie_name in pre_cookies:
                    if cookie_name in post_cookies:
                        if pre_cookies[cookie_name] == post_cookies[cookie_name]:
                            self.evidence.log_potential_exploit("session_testing", {
                                "type": "session_fixation",
                                "url": endpoint,
                                "cookie_name": cookie_name,
                                "severity": "high",
                                "description": "Session ID not rotated after login attempt",
                            })
                            self.state.enrich("potential_vulnerabilities", [{
                                "type": "session_fixation",
                                "url": endpoint,
                                "severity": "high",
                                "description": f"Session cookie '{cookie_name}' not rotated on login",
                            }])
            except Exception as e:
                self.logger.debug(f"Session fixation test failed for {endpoint}: {e}")

    async def _session_lifecycle(self):
        self.logger.info("Starting session lifecycle testing")
        # This requires authenticated session - check for auth profile
        auth_profile = self.config.get_auth_profile("default") if hasattr(self.config, 'get_auth_profile') else None

        if not auth_profile:
            self.logger.info("No auth profile configured, skipping session lifecycle tests")
            return

        # TODO: Test session invalidation on logout
        # TODO: Test session reuse after logout
        # TODO: Test session timeout
        self.logger.info("Session lifecycle tests require authenticated session (TODO: implement with auth profile)")

    def _extract_session_cookies(self, resp) -> dict:
        cookies = {}
        session_names = ["session", "sessionid", "phpsessid", "jsessionid",
                         "sid", "sess", "token", "auth", "connect.sid"]
        headers = resp.headers if hasattr(resp, 'headers') else {}
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                name_match = re.match(r'([^=]+)=([^;]+)', value)
                if name_match:
                    name = name_match.group(1).strip().lower()
                    val = name_match.group(2).strip()
                    if any(sn in name for sn in session_names):
                        cookies[name_match.group(1).strip()] = val
        return cookies

    def _http_get(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    def _http_post(self, url: str, data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data=data)