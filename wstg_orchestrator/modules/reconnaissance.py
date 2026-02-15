# wstg_orchestrator/modules/reconnaissance.py
import asyncio
import re
import shlex
import subprocess as _subprocess
from urllib.parse import urlparse, parse_qs

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.cli_handler import cli_input
from wstg_orchestrator.utils.command_runner import CommandRunner
from wstg_orchestrator.utils.parser_utils import (
    extract_params_from_url,
    extract_urls_from_text,
    detect_id_patterns,
    strip_scheme,
    parse_url_components,
)


class ReconModule(BaseModule):
    PHASE_NAME = "reconnaissance"
    SUBCATEGORIES = ["asn_enumeration", "passive_osint", "url_harvesting", "live_host_validation", "parameter_harvesting"]
    EVIDENCE_SUBDIRS = ["tool_output", "parsed", "evidence", "screenshots"]
    _CIDR_RE = re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}'  # IPv4
        r'|[0-9a-fA-F:]+/\d{1,3})'                        # IPv6
    )
    TOOL_INSTALL_COMMANDS = {
        "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
        "whois": "apt install whois",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["subfinder", "amass", "gau", "httpx", "whois"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("asn_enumeration"):
            await self._asn_enumeration()
            self.mark_subcategory_complete("asn_enumeration")

        if not self.should_skip_subcategory("passive_osint"):
            await self._passive_osint()
            self.mark_subcategory_complete("passive_osint")

        if not self.should_skip_subcategory("url_harvesting"):
            await self._url_harvesting()
            self.mark_subcategory_complete("url_harvesting")

        if not self.should_skip_subcategory("live_host_validation"):
            await self._live_host_validation()
            self.mark_subcategory_complete("live_host_validation")

        if not self.should_skip_subcategory("parameter_harvesting"):
            await self._parameter_harvesting()
            self.mark_subcategory_complete("parameter_harvesting")

    def _get_target_domains(self) -> list[str]:
        """Return deduplicated list of domains to enumerate subdomains for.

        Uses enumeration_domains from config which combines base_domain
        and wildcard_urls only. in_scope_urls are excluded.
        Falls back to base_domain if enumeration_domains is unavailable.
        """
        domains = getattr(self.config, "enumeration_domains", None) or []
        if not domains:
            domains = [self.config.base_domain]
        return domains

    def _parse_amass_org_output(self, stdout: str, company_name: str) -> list[dict]:
        """Parse amass intel -org output. Return list of {asn, cidr, org} dicts
        for lines where org field contains company_name (case-insensitive)."""
        results = []
        company_lower = company_name.lower()
        asn_re = re.compile(r'(AS\d+)')

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if company_lower not in line.lower():
                continue
            asn_match = asn_re.search(line)
            if not asn_match:
                continue
            cidr_match = self._CIDR_RE.search(line)
            results.append({
                "asn": asn_match.group(1),
                "cidr": cidr_match.group(1) if cidr_match else None,
                "org": line,
            })
        return results

    def _parse_whois_radb_output(self, stdout: str) -> list[str]:
        """Parse whois RADB output for route:/route6: lines, return list of CIDRs."""
        cidrs = []
        route_re = re.compile(r'^route6?:\s+(.+)', re.MULTILINE)
        for match in route_re.finditer(stdout):
            cidr = match.group(1).strip()
            if cidr:
                cidrs.append(cidr)
        return cidrs

    def _prompt_install_tool(self, tool_name: str, install_cmd: str) -> bool:
        """Prompt user to install a missing tool. Returns True if installed successfully."""
        self.logger.warning(f"{tool_name} not found.")
        answer = cli_input(f"Install {tool_name} with `{install_cmd}`? [y/N]: ").strip().lower()
        if answer != "y":
            self.logger.info(f"User declined to install {tool_name}, skipping")
            return False
        try:
            result = _subprocess.run(shlex.split(install_cmd), capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.logger.info(f"{tool_name} installed successfully")
                return True
            self.logger.error(f"Failed to install {tool_name}: {result.stderr}")
        except Exception as e:
            self.logger.error(f"Error installing {tool_name}: {e}")
        return False

    async def _run_amass_intel_org(self, company_name: str):
        """Run amass intel -org to discover ASNs for a company."""
        self.logger.info(f"Running amass intel -org for: {company_name}")
        result = self._cmd.run("amass", ["intel", "-org", company_name], timeout=300)
        if result.tool_missing:
            if self._prompt_install_tool("amass", self.TOOL_INSTALL_COMMANDS["amass"]):
                result = self._cmd.run("amass", ["intel", "-org", company_name], timeout=300)
            else:
                return result
        if result.returncode == 0 and result.stdout.strip():
            self.evidence.log_tool_output("reconnaissance", "amass_intel_org", result.stdout)
        return result

    async def _run_amass_intel_asn(self, asn: str):
        """Run amass intel -asn to get IP ranges for an ASN."""
        self.logger.info(f"Running amass intel -asn for: {asn}")
        result = self._cmd.run("amass", ["intel", "-asn", asn], timeout=120)
        if result.returncode == 0 and result.stdout.strip():
            self.evidence.log_tool_output("reconnaissance", f"amass_intel_asn_{asn}", result.stdout)
        return result

    async def _run_whois_radb(self, asn: str):
        """Run whois against RADB to look up IP ranges for an ASN."""
        self.logger.info(f"Running whois RADB lookup for: {asn}")
        result = self._cmd.run("whois", ["-h", "whois.radb.net", "--", f"-i origin {asn}"], timeout=30)
        if result.tool_missing:
            if self._prompt_install_tool("whois", self.TOOL_INSTALL_COMMANDS["whois"]):
                result = self._cmd.run("whois", ["-h", "whois.radb.net", "--", f"-i origin {asn}"], timeout=30)
            else:
                return result
        if result.returncode == 0 and result.stdout.strip():
            self.evidence.log_tool_output("reconnaissance", f"whois_radb_{asn}", result.stdout)
        return result

    async def _lookup_asn_ip_ranges(self, asn_list: list[str]) -> list[str]:
        """Look up IP ranges for each ASN. Try amass first, fall back to whois RADB."""
        all_cidrs = []

        for asn in asn_list:
            cidrs_for_asn = []

            # Try amass intel -asn first
            result = await self._run_amass_intel_asn(asn)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    line = line.strip()
                    match = self._CIDR_RE.search(line)
                    if match:
                        cidrs_for_asn.append(match.group(1))

            # Fall back to whois RADB if amass returned nothing
            if not cidrs_for_asn:
                self.logger.info(f"amass returned no ranges for {asn}, trying whois RADB")
                result = await self._run_whois_radb(asn)
                if result.returncode == 0 and result.stdout.strip():
                    cidrs_for_asn = self._parse_whois_radb_output(result.stdout)

            if not cidrs_for_asn:
                self.logger.warning(f"No IP ranges found for {asn}")

            all_cidrs.extend(cidrs_for_asn)

        return list(dict.fromkeys(all_cidrs))

    async def _asn_enumeration(self):
        """Discover ASNs for the target company and resolve their IP ranges."""
        company_name = self.config.company_name
        if not company_name:
            self.logger.warning("No company_name configured, skipping ASN enumeration")
            return

        self.logger.info(f"Starting ASN enumeration for: {company_name}")

        # Step 1: Discover ASNs via amass intel -org
        result = await self._run_amass_intel_org(company_name)
        if result.tool_missing or result.returncode != 0:
            self.logger.warning("amass intel -org failed, skipping ASN enumeration")
            return

        parsed = self._parse_amass_org_output(result.stdout, company_name)
        if not parsed:
            self.logger.info("No ASNs found matching company name")
            return

        # Collect ASNs and any inline CIDRs
        asns = list(dict.fromkeys(entry["asn"] for entry in parsed))
        inline_cidrs = [entry["cidr"] for entry in parsed if entry["cidr"]]

        self.state.enrich("asns", asns)
        self.evidence.log_parsed("reconnaissance", "asns", asns)
        self.logger.info(f"Found {len(asns)} ASNs: {', '.join(asns)}")

        # Step 2: Look up IP ranges for each ASN
        looked_up_cidrs = await self._lookup_asn_ip_ranges(asns)

        # Merge inline + looked-up CIDRs, deduplicate
        all_cidrs = list(dict.fromkeys(inline_cidrs + looked_up_cidrs))

        self.state.enrich("ip_ranges", all_cidrs)
        self.evidence.log_parsed("reconnaissance", "ip_ranges", all_cidrs)
        self.logger.info(f"Found {len(all_cidrs)} IP ranges")

    async def _passive_osint(self):
        self.logger.info("Starting passive OSINT - subdomain enumeration")
        all_subdomains = []

        target_domains = self._get_target_domains()
        for domain in target_domains:
            subfinder_results = await self._run_subfinder(domain)
            all_subdomains.extend(subfinder_results)

        all_subdomains = list(set(self._filter_in_scope(all_subdomains)))
        self.state.enrich("discovered_subdomains", all_subdomains)
        self.evidence.log_parsed("reconnaissance", "subdomains", all_subdomains)
        self.logger.info(f"Found {len(all_subdomains)} subdomains")

    async def _url_harvesting(self):
        """Harvest URLs from gau/wayback and parse into three buckets."""
        self.logger.info("Starting URL harvesting")

        gau_results = await self._run_gau()
        wayback_results = await self._run_wayback()
        all_urls = gau_results + wayback_results

        new_subdomains = []
        new_endpoints = []
        new_params = []

        for url in all_urls:
            components = parse_url_components(url)
            hostname = components["hostname"]

            if not hostname:
                continue

            # Always extract hostname -> discovered_subdomains
            new_subdomains.append(hostname)

            if components["has_query"]:
                # URL with query string -> parameters (full) + endpoints (base path)
                new_params.append(components["full"])
                new_endpoints.append(components["path"])
            elif components["path"] != hostname:
                # URL with path but no query -> endpoints (classification as
                # endpoint vs directory_path happens later during probing)
                new_endpoints.append(components["path"])

        new_subdomains = list(set(self._filter_in_scope(new_subdomains)))
        new_endpoints = list(set(new_endpoints))
        new_params = list(set(new_params))

        self.state.enrich("discovered_subdomains", new_subdomains)
        self.state.enrich("endpoints", new_endpoints)
        self.state.enrich("parameters", new_params)
        self.evidence.log_parsed("reconnaissance", "harvested_urls", all_urls)
        self.logger.info(
            f"Harvested {len(new_subdomains)} subdomains, "
            f"{len(new_endpoints)} endpoints, {len(new_params)} parameters"
        )

    async def _run_subfinder(self, domain: str | None = None) -> list[str]:
        target = domain or self.config.base_domain
        self.logger.info(f"Running subfinder for domain: {target}")
        result = self._cmd.run(
            "subfinder", ["-d", target, "-silent"], timeout=300,
        )
        if result.tool_missing:
            self.logger.warning("subfinder not found, trying amass")
            return await self._run_amass(target)
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "subfinder", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_amass(self, domain: str | None = None) -> list[str]:
        target = domain or self.config.base_domain
        self.logger.info(f"Running amass for domain: {target}")
        result = self._cmd.run(
            "amass", ["enum", "-passive", "-d", target], timeout=600,
        )
        if result.tool_missing:
            self.logger.warning("amass not found, skipping subdomain enumeration tools")
            return []
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "amass", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_gau(self) -> list[str]:
        all_urls = []
        for domain in self._get_target_domains():
            self.logger.info(f"Running gau for domain: {domain}")
            result = self._cmd.run(
                "gau", [domain, "--subs"], timeout=300,
            )
            if result.tool_missing:
                self.logger.warning("gau not found, skipping URL harvesting from gau")
                return []
            if result.returncode == 0:
                self.evidence.log_tool_output("reconnaissance", "gau", result.stdout)
                all_urls.extend(line.strip() for line in result.stdout.splitlines() if line.strip())
        return all_urls

    async def _run_wayback(self) -> list[str]:
        # Wayback Machine CDX API - no external tool needed
        all_urls = []
        for domain in self._get_target_domains():
            try:
                import requests
                self.logger.info(f"Fetching Wayback URLs for domain: {domain}")
                resp = requests.get(
                    f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
                    timeout=60,
                )
                if resp.status_code == 200:
                    urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
                    self.evidence.log_tool_output("reconnaissance", "wayback", resp.text)
                    all_urls.extend(urls)
            except Exception as e:
                self.logger.warning(f"Wayback fetch failed for {domain}: {e}")
        return all_urls

    async def _live_host_validation(self):
        self.logger.info("Starting live host validation")
        subdomains = list(self.state.get("discovered_subdomains") or [])

        # Merge in_scope_urls (extract hostnames from paths)
        in_scope = getattr(self.config, "in_scope_urls", []) or []
        for url in in_scope:
            hostname = url.split("/")[0].split(":")[0]
            if hostname and hostname not in subdomains:
                subdomains.append(hostname)

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
        import tempfile, os, json
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
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    url = entry.get("url", "")
                    if url:
                        hostname = parse_url_components(url)["hostname"]
                        if hostname:
                            live.append(hostname)
                    for tech in entry.get("tech", []):
                        techs.append(tech)
                except json.JSONDecodeError:
                    if line.strip():
                        live.append(strip_scheme(line.strip()))
        return live, list(set(techs))

    async def _fallback_probe(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
        import requests
        live = []
        techs = []
        for sub in subdomains:
            for scheme in ["https", "http"]:
                try:
                    resp = requests.get(f"{scheme}://{sub}", timeout=10, allow_redirects=True)
                    live.append(sub)  # Store bare hostname, not full URL
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
