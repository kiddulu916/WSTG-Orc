# wstg_orchestrator/modules/fingerprinting.py
import json
import re
import xml.etree.ElementTree as ET

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner


class FingerprintingModule(BaseModule):
    PHASE_NAME = "fingerprinting"
    SUBCATEGORIES = ["service_scanning", "header_analysis", "error_analysis", "cve_correlation"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["nmap", "whatweb"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("service_scanning"):
            await self._service_scanning()
            self.mark_subcategory_complete("service_scanning")

        if not self.should_skip_subcategory("header_analysis"):
            await self._header_analysis()
            self.mark_subcategory_complete("header_analysis")

        if not self.should_skip_subcategory("error_analysis"):
            await self._error_analysis()
            self.mark_subcategory_complete("error_analysis")

        if not self.should_skip_subcategory("cve_correlation"):
            await self._cve_correlation()
            self.mark_subcategory_complete("cve_correlation")

    async def _service_scanning(self):
        self.logger.info("Starting service scanning")
        live_hosts = self.state.get("live_hosts") or []
        all_ports = []
        all_versions = []

        # Extract hostnames for nmap
        from urllib.parse import urlparse
        hosts = list(set(urlparse(h).hostname for h in live_hosts if urlparse(h).hostname))

        if hosts and self._cmd.is_tool_available("nmap"):
            for host in hosts:
                result = self._cmd.run(
                    "nmap", ["-sV", "-oX", "-", host], timeout=300,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("fingerprinting", f"nmap_{host}", result.stdout)
                    parsed = self._parse_nmap_xml(result.stdout)
                    all_ports.extend(parsed["ports"])
                    all_versions.extend(parsed["server_versions"])
        else:
            self.logger.warning("nmap not available or no hosts to scan")

        # WhatWeb integration
        if self._cmd.is_tool_available("whatweb"):
            for host_url in live_hosts[:20]:  # limit to first 20
                result = self._cmd.run(
                    "whatweb", ["--color=never", "-q", "--log-json=-", host_url], timeout=60,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("fingerprinting", "whatweb", result.stdout)
                    try:
                        for line in result.stdout.splitlines():
                            if line.strip():
                                entry = json.loads(line)
                                for plugin_name, plugin_data in entry.get("plugins", {}).items():
                                    versions = plugin_data.get("version", [])
                                    for v in versions:
                                        all_versions.append(f"{plugin_name}/{v}")
                    except (json.JSONDecodeError, AttributeError):
                        pass

        self.state.enrich("open_ports", all_ports)
        self.state.enrich("server_versions", list(set(all_versions)))
        self.evidence.log_parsed("fingerprinting", "service_scan_results", {
            "ports": all_ports, "versions": list(set(all_versions)),
        })

    def _parse_nmap_xml(self, xml_str: str) -> dict:
        ports = []
        versions = []
        try:
            root = ET.fromstring(xml_str)
            for host in root.findall(".//host"):
                addr_el = host.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""
                for port_el in host.findall(".//port"):
                    port_id = int(port_el.get("portid", 0))
                    protocol = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    service_el = port_el.find("service")
                    service_name = ""
                    product = ""
                    version = ""
                    if service_el is not None:
                        service_name = service_el.get("name", "")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                    ports.append({
                        "host": addr, "port": port_id, "protocol": protocol,
                        "state": state, "service": service_name,
                        "product": product, "version": version,
                    })
                    if product:
                        ver_str = f"{product}/{version}" if version else product
                        versions.append(ver_str)
        except ET.ParseError as e:
            self.logger.warning(f"Failed to parse nmap XML: {e}")
        return {"ports": ports, "server_versions": versions}

    async def _header_analysis(self):
        self.logger.info("Starting header analysis")
        live_hosts = self.state.get("live_hosts") or []
        all_versions = []
        all_frameworks = []

        for host_url in live_hosts:
            try:
                resp = await self._make_request(host_url)
                results = await self._analyze_headers(host_url, response=resp)
                all_versions.extend(results.get("server_versions", []))
                all_frameworks.extend(results.get("frameworks", []))
            except Exception as e:
                self.logger.debug(f"Header analysis failed for {host_url}: {e}")

        self.state.enrich("server_versions", list(set(all_versions)))
        self.state.enrich("frameworks", list(set(all_frameworks)))

    async def _make_request(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        from wstg_orchestrator.utils.scope_checker import ScopeChecker
        from wstg_orchestrator.utils.rate_limit_handler import RateLimiter
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    async def _analyze_headers(self, url: str, response=None) -> dict:
        versions = []
        frameworks = []

        if response is None:
            response = await self._make_request(url)

        headers = response.headers if hasattr(response, 'headers') else {}

        server = headers.get("Server", "")
        if server:
            versions.append(server)

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            frameworks.append(powered_by)

        asp_version = headers.get("X-AspNet-Version", "")
        if asp_version:
            frameworks.append(f"ASP.NET/{asp_version}")

        generator = headers.get("X-Generator", "")
        if generator:
            frameworks.append(generator)

        # Cookie analysis for framework hints
        set_cookie = headers.get("Set-Cookie", "")
        if "PHPSESSID" in set_cookie:
            frameworks.append("PHP")
        if "JSESSIONID" in set_cookie:
            frameworks.append("Java")
        if "ASP.NET" in set_cookie:
            frameworks.append("ASP.NET")
        if "laravel_session" in set_cookie:
            frameworks.append("Laravel")
        if "csrftoken" in set_cookie and "django" not in str(frameworks).lower():
            frameworks.append("Django (possible)")

        self.evidence.log_request("fingerprinting", {"method": "GET", "url": url})
        self.evidence.log_response("fingerprinting", {
            "url": url, "status": response.status_code,
            "headers": dict(headers),
        })

        return {"server_versions": versions, "frameworks": frameworks}

    async def _error_analysis(self):
        self.logger.info("Starting error analysis")
        live_hosts = self.state.get("live_hosts") or []
        error_paths = [
            "/nonexistent_path_" + "x" * 50,
            "/%00", "/~", "/..;/",
            "/index.php.bak", "/web.config", "/.env",
        ]

        for host_url in live_hosts[:10]:
            for path in error_paths:
                try:
                    resp = await self._make_request(f"{host_url.rstrip('/')}{path}")
                    if resp.status_code in [500, 502, 503]:
                        # Check for stack traces or version info
                        body = resp.text if hasattr(resp, 'text') else ""
                        stack_patterns = [
                            r"(Traceback.*?(?:Error|Exception).*?)(?:\n\n|\Z)",
                            r"(at\s+[\w\.$]+\([\w\.]+:\d+\))",
                            r"(Version:\s*[\d\.]+)",
                            r"(PHP (?:Fatal|Warning|Notice).*)",
                        ]
                        for pattern in stack_patterns:
                            matches = re.findall(pattern, body, re.DOTALL)
                            if matches:
                                self.evidence.log_potential_exploit("fingerprinting", {
                                    "type": "information_disclosure",
                                    "url": f"{host_url}{path}",
                                    "details": matches[0][:500],
                                    "severity": "low",
                                })
                except Exception:
                    continue

    async def _cve_correlation(self):
        self.logger.info("Starting CVE correlation")
        versions = self.state.get("server_versions") or []
        all_cves = []

        for version_str in versions:
            try:
                import requests as req_lib
                # Use NIST NVD API or cve.circl.lu
                parts = version_str.split("/")
                if len(parts) >= 2:
                    product = parts[0].lower()
                    version = parts[1]
                    resp = req_lib.get(
                        f"https://cve.circl.lu/api/search/{product}",
                        timeout=15,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            for cve in data[:5]:  # top 5 per product
                                cve_id = cve.get("id", "")
                                summary = cve.get("summary", "")
                                all_cves.append({
                                    "cve_id": cve_id,
                                    "product": version_str,
                                    "summary": summary[:200],
                                })
            except Exception as e:
                self.logger.debug(f"CVE lookup failed for {version_str}: {e}")

        if all_cves:
            self.state.enrich("inferred_cves", all_cves)
            self.evidence.log_parsed("fingerprinting", "inferred_cves", all_cves)
            self.logger.info(f"Found {len(all_cves)} potential CVEs")