# wstg_orchestrator/modules/configuration_testing.py
import re

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner


CLOUD_PATTERNS = [
    (r'[\w\-]+\.s3[\.\-](?:[\w\-]+\.)?amazonaws\.com', "aws_s3"),
    (r's3://[\w\-]+', "aws_s3"),
    (r'storage\.googleapis\.com/[\w\-]+', "gcs"),
    (r'[\w\-]+\.storage\.googleapis\.com', "gcs"),
    (r'[\w\-]+\.blob\.core\.windows\.net', "azure_blob"),
]

BYPASS_403_HEADERS = [
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

BYPASS_403_PATHS = [
    "/{path}/.",
    "/{path}//",
    "/{path}%20",
    "/{path}%09",
    "/{path}..;/",
    "/{path};",
]


class ConfigTestingModule(BaseModule):
    PHASE_NAME = "configuration_testing"
    SUBCATEGORIES = [
        "metafile_testing", "directory_bruteforce",
        "http_method_testing", "cloud_storage_enum",
    ]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["gobuster", "dirsearch"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("metafile_testing"):
            await self._metafile_testing()
            self.mark_subcategory_complete("metafile_testing")

        if not self.should_skip_subcategory("directory_bruteforce"):
            await self._directory_bruteforce()
            self.mark_subcategory_complete("directory_bruteforce")

        if not self.should_skip_subcategory("http_method_testing"):
            await self._http_method_testing()
            self.mark_subcategory_complete("http_method_testing")

        if not self.should_skip_subcategory("cloud_storage_enum"):
            await self._cloud_storage_enum()
            self.mark_subcategory_complete("cloud_storage_enum")

    async def _metafile_testing(self):
        self.logger.info("Starting metafile testing")
        live_hosts = self.state.get("live_hosts") or []
        all_paths = []

        for host_url in live_hosts:
            base = host_url.rstrip("/")
            # robots.txt
            try:
                resp = self._http_get(f"{base}/robots.txt")
                if resp.status_code == 200 and "disallow" in resp.text.lower():
                    paths = self._parse_robots_txt(resp.text)
                    all_paths.extend(paths)
                    self.evidence.log_tool_output("configuration_testing", f"robots_{base}", resp.text)
            except Exception:
                pass

            # sitemap.xml
            try:
                resp = self._http_get(f"{base}/sitemap.xml")
                if resp.status_code == 200 and "<url" in resp.text.lower():
                    urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
                    self.state.enrich("endpoints", urls)
                    self.evidence.log_tool_output("configuration_testing", f"sitemap_{base}", resp.text)
            except Exception:
                pass

        if all_paths:
            self.state.enrich("exposed_admin_paths", all_paths)
            self.evidence.log_parsed("configuration_testing", "robots_paths", all_paths)

    def _parse_robots_txt(self, content: str) -> list[str]:
        paths = []
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
        return paths

    async def _directory_bruteforce(self):
        self.logger.info("Starting directory brute forcing")
        live_hosts = self.state.get("live_hosts") or []
        found_paths = []

        for host_url in live_hosts[:5]:  # Limit to first 5 hosts
            if self._cmd.is_tool_available("gobuster"):
                result = self._cmd.run(
                    "gobuster",
                    ["dir", "-u", host_url, "-w", "/usr/share/wordlists/dirb/common.txt",
                     "-q", "--no-color", "-t", "10"],
                    timeout=300,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("configuration_testing", "gobuster", result.stdout)
                    for line in result.stdout.splitlines():
                        if "(Status:" in line:
                            path_match = re.match(r'(/\S+)', line)
                            if path_match:
                                found_path = path_match.group(1)
                                found_paths.append(f"{host_url.rstrip('/')}{found_path}")
                                status_match = re.search(r'Status:\s*(\d+)', line)
                                if status_match and status_match.group(1) == "403":
                                    await self._try_403_bypass(host_url, found_path)
            else:
                self.logger.warning("gobuster not found, skipping directory brute force")

        if found_paths:
            self.state.enrich("endpoints", found_paths)

    async def _try_403_bypass(self, base_url: str, path: str):
        base = base_url.rstrip("/")
        # Header-based bypasses
        for header_template in BYPASS_403_HEADERS:
            headers = {k: v.format(path=path) for k, v in header_template.items()}
            try:
                resp = self._http_get(f"{base}{path}", extra_headers=headers)
                if resp.status_code == 200:
                    self.evidence.log_potential_exploit("configuration_testing", {
                        "type": "403_bypass",
                        "url": f"{base}{path}",
                        "bypass_method": str(headers),
                        "severity": "medium",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "403_bypass", "url": f"{base}{path}",
                        "severity": "medium",
                        "description": f"403 bypass via headers: {headers}",
                    }])
            except Exception:
                continue

        # Path-based bypasses
        for path_template in BYPASS_403_PATHS:
            bypass_path = path_template.format(path=path.rstrip("/"))
            try:
                resp = self._http_get(f"{base}{bypass_path}")
                if resp.status_code == 200:
                    self.evidence.log_potential_exploit("configuration_testing", {
                        "type": "403_bypass",
                        "url": f"{base}{bypass_path}",
                        "bypass_method": f"path: {bypass_path}",
                        "severity": "medium",
                    })
            except Exception:
                continue

    async def _http_method_testing(self):
        self.logger.info("Starting HTTP method testing")
        live_hosts = self.state.get("live_hosts") or []

        for host_url in live_hosts:
            # OPTIONS request
            try:
                resp = self._http_request("OPTIONS", host_url)
                allow = resp.headers.get("Allow", "")
                if allow:
                    self.evidence.log_parsed("configuration_testing", f"methods_{host_url}", {
                        "url": host_url, "allowed_methods": allow,
                    })
                    # Check for dangerous methods
                    dangerous = {"PUT", "DELETE", "TRACE"}
                    allowed_set = {m.strip().upper() for m in allow.split(",")}
                    found_dangerous = dangerous & allowed_set

                    if found_dangerous:
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "dangerous_http_methods",
                            "url": host_url,
                            "methods": list(found_dangerous),
                            "severity": "medium",
                            "description": f"Dangerous HTTP methods enabled: {found_dangerous}",
                        }])

                    # TRACE XST test
                    if "TRACE" in allowed_set:
                        trace_resp = self._http_request("TRACE", host_url)
                        if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
                            self.evidence.log_confirmed_exploit("configuration_testing", {
                                "type": "xst",
                                "url": host_url,
                                "severity": "low",
                                "description": "Cross-Site Tracing (XST) - TRACE method reflects request",
                            })
            except Exception as e:
                self.logger.debug(f"Method testing failed for {host_url}: {e}")

    async def _cloud_storage_enum(self):
        self.logger.info("Starting cloud storage enumeration")
        endpoints = self.state.get("endpoints") or []
        live_hosts = self.state.get("live_hosts") or []
        all_urls = endpoints + live_hosts

        cloud_assets = self._detect_cloud_patterns(all_urls)

        # Test public access for each detected asset
        for asset in cloud_assets:
            try:
                resp = self._http_get(asset["url"])
                asset["public_read"] = resp.status_code == 200
                if resp.status_code == 200:
                    self.evidence.log_potential_exploit("configuration_testing", {
                        "type": "public_cloud_storage",
                        "url": asset["url"],
                        "provider": asset["provider"],
                        "severity": "high",
                        "description": f"Publicly readable {asset['provider']} storage",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "public_cloud_storage",
                        "url": asset["url"],
                        "severity": "high",
                        "description": f"Publicly readable {asset['provider']} storage",
                    }])
            except Exception:
                asset["public_read"] = False

        if cloud_assets:
            self.state.enrich("cloud_assets", cloud_assets)
            self.evidence.log_parsed("configuration_testing", "cloud_assets", cloud_assets)

    def _detect_cloud_patterns(self, urls: list[str]) -> list[dict]:
        found = []
        for url in urls:
            for pattern, provider in CLOUD_PATTERNS:
                if re.search(pattern, url, re.I):
                    found.append({"url": url, "provider": provider})
                    break
        return found

    def _http_get(self, url: str, extra_headers: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url, headers=extra_headers)

    def _http_request(self, method: str, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.request(method, url)