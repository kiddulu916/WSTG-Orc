# wstg_orchestrator/modules/reconnaissance.py
import asyncio
import re
from urllib.parse import urlparse, parse_qs

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner
from wstg_orchestrator.utils.parser_utils import (
    extract_params_from_url,
    extract_urls_from_text,
    detect_id_patterns,
)


class ReconModule(BaseModule):
    PHASE_NAME = "reconnaissance"
    SUBCATEGORIES = ["passive_osint", "live_host_validation", "parameter_harvesting"]
    EVIDENCE_SUBDIRS = ["tool_output", "parsed", "evidence", "screenshots"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["subfinder", "amass", "gau", "httpx"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("passive_osint"):
            await self._passive_osint()
            self.mark_subcategory_complete("passive_osint")

        if not self.should_skip_subcategory("live_host_validation"):
            await self._live_host_validation()
            self.mark_subcategory_complete("live_host_validation")

        if not self.should_skip_subcategory("parameter_harvesting"):
            await self._parameter_harvesting()
            self.mark_subcategory_complete("parameter_harvesting")

    async def _passive_osint(self):
        self.logger.info("Starting passive OSINT")
        all_subdomains = []

        subfinder_results = await self._run_subfinder()
        all_subdomains.extend(subfinder_results)

        gau_results = await self._run_gau()
        wayback_results = await self._run_wayback()
        all_urls = gau_results + wayback_results

        # Extract subdomains from URLs
        for url in all_urls:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            if parsed.hostname:
                all_subdomains.append(parsed.hostname)

        all_subdomains = list(set(self._filter_in_scope(all_subdomains)))
        all_urls = list(set(self._filter_in_scope(all_urls)))

        self.state.enrich("discovered_subdomains", all_subdomains)
        self.state.enrich("endpoints", all_urls)
        self.evidence.log_parsed("reconnaissance", "subdomains", all_subdomains)
        self.evidence.log_parsed("reconnaissance", "historical_urls", all_urls)
        self.logger.info(f"Found {len(all_subdomains)} subdomains, {len(all_urls)} URLs")

    async def _run_subfinder(self) -> list[str]:
        result = self._cmd.run(
            "subfinder", ["-d", self.config.base_domain, "-silent"], timeout=300,
        )
        if result.tool_missing:
            self.logger.warning("subfinder not found, trying amass")
            return await self._run_amass()
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "subfinder", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_amass(self) -> list[str]:
        result = self._cmd.run(
            "amass", ["enum", "-passive", "-d", self.config.base_domain], timeout=600,
        )
        if result.tool_missing:
            self.logger.warning("amass not found, skipping subdomain enumeration tools")
            return []
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "amass", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_gau(self) -> list[str]:
        result = self._cmd.run(
            "gau", [self.config.base_domain, "--subs"], timeout=300,
        )
        if result.tool_missing:
            self.logger.warning("gau not found, skipping URL harvesting from gau")
            return []
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "gau", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_wayback(self) -> list[str]:
        # Wayback Machine CDX API - no external tool needed
        try:
            from wstg_orchestrator.utils.http_utils import HttpClient
            # Use raw requests to avoid scope check on archive.org
            import requests
            resp = requests.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{self.config.base_domain}/*&output=text&fl=original&collapse=urlkey",
                timeout=60,
            )
            if resp.status_code == 200:
                urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
                self.evidence.log_tool_output("reconnaissance", "wayback", resp.text)
                return urls
        except Exception as e:
            self.logger.warning(f"Wayback fetch failed: {e}")
        return []

    async def _live_host_validation(self):
        self.logger.info("Starting live host validation")
        subdomains = self.state.get("discovered_subdomains") or []
        if not subdomains:
            subdomains = [self.config.base_domain]

        live_hosts = []
        technologies = []

        if self._cmd.is_tool_available("httpx"):
            live_hosts, technologies = await self._run_httpx(subdomains)
        else:
            self.logger.warning("httpx not found, using fallback HTTP probing")
            live_hosts, technologies = await self._fallback_probe(subdomains)

        self.state.enrich("live_hosts", live_hosts)
        self.state.enrich("technologies", technologies)
        self.evidence.log_parsed("reconnaissance", "live_hosts", live_hosts)
        self.logger.info(f"Found {len(live_hosts)} live hosts")

    async def _run_httpx(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
        import tempfile, os
        fd, input_file = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(subdomains))

        result = self._cmd.run(
            "httpx", ["-l", input_file, "-silent", "-tech-detect", "-status-code", "-json"],
            timeout=600,
        )
        os.unlink(input_file)

        live = []
        techs = []
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "httpx", result.stdout)
            import json
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    url = entry.get("url", "")
                    if url:
                        live.append(url)
                    for tech in entry.get("tech", []):
                        techs.append(tech)
                except json.JSONDecodeError:
                    if line.strip():
                        live.append(line.strip())
        return live, list(set(techs))

    async def _fallback_probe(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
        import requests
        live = []
        techs = []
        for sub in subdomains:
            for scheme in ["https", "http"]:
                try:
                    resp = requests.get(f"{scheme}://{sub}", timeout=10, allow_redirects=True)
                    live.append(f"{scheme}://{sub}")
                    server = resp.headers.get("Server", "")
                    if server:
                        techs.append(server)
                    powered = resp.headers.get("X-Powered-By", "")
                    if powered:
                        techs.append(powered)
                    break
                except Exception:
                    continue
        return live, list(set(techs))

    async def _parameter_harvesting(self):
        self.logger.info("Starting parameter harvesting")
        endpoints = self.state.get("endpoints") or []
        live_hosts = self.state.get("live_hosts") or []

        all_params = []
        idor_candidates = []

        # Extract params from known URLs
        for url in endpoints:
            params = extract_params_from_url(url)
            for name, value in params.items():
                all_params.append({"url": url, "name": name, "value": value, "method": "GET"})

        # Detect ID patterns
        id_patterns = detect_id_patterns(endpoints + live_hosts)
        for pattern in id_patterns:
            idor_candidates.append(pattern)

        # TODO: JS file parsing for hidden endpoints
        # TODO: Form extraction from live hosts

        self.state.enrich("parameters", all_params)
        self.state.enrich("potential_idor_candidates", idor_candidates)
        self.evidence.log_parsed("reconnaissance", "parameters", all_params)
        self.evidence.log_parsed("reconnaissance", "idor_candidates", idor_candidates)
        self.logger.info(f"Found {len(all_params)} parameters, {len(idor_candidates)} IDOR candidates")

    def _filter_in_scope(self, items: list[str]) -> list[str]:
        return [item for item in items if self.scope.is_in_scope(item)]