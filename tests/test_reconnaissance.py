# tests/test_reconnaissance.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.reconnaissance import ReconModule


@pytest.fixture
def recon_module():
    state = MagicMock()
    state.get.return_value = []
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.enumeration_domains = ["example.com"]
    config.get_tool_config.return_value = {}
    config.in_scope_urls = []
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    callback = MagicMock()
    return ReconModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(recon_module):
    assert recon_module.PHASE_NAME == "reconnaissance"


def test_subcategories(recon_module):
    assert "passive_osint" in recon_module.SUBCATEGORIES
    assert "url_harvesting" in recon_module.SUBCATEGORIES
    assert "live_host_validation" in recon_module.SUBCATEGORIES
    assert "parameter_harvesting" in recon_module.SUBCATEGORIES


@pytest.mark.asyncio
async def test_passive_osint_runs_subfinder(recon_module):
    with patch.object(recon_module, '_run_subfinder', new_callable=AsyncMock, return_value=["sub.example.com"]):
        await recon_module._passive_osint()
        recon_module.state.enrich.assert_any_call("discovered_subdomains", ["sub.example.com"])


@pytest.mark.asyncio
async def test_passive_osint_uses_enumeration_domains(recon_module):
    """Subdomain enumeration should iterate over all enumeration domains."""
    recon_module.config.enumeration_domains = ["example.com", "api.example.com", "partner.com"]
    calls = []

    async def mock_subfinder(domain=None):
        calls.append(domain)
        return [f"sub.{domain}"]

    with patch.object(recon_module, '_run_subfinder', side_effect=mock_subfinder):
        await recon_module._passive_osint()
        assert calls == ["example.com", "api.example.com", "partner.com"]


def test_get_target_domains_from_enumeration_domains(recon_module):
    """_get_target_domains returns enumeration_domains when available."""
    recon_module.config.enumeration_domains = ["example.com", "api.example.com"]
    assert recon_module._get_target_domains() == ["example.com", "api.example.com"]


def test_get_target_domains_fallback(recon_module):
    """_get_target_domains falls back to base_domain when enumeration_domains is empty."""
    recon_module.config.enumeration_domains = []
    assert recon_module._get_target_domains() == ["example.com"]


@pytest.mark.asyncio
async def test_scope_filter_applied(recon_module):
    recon_module.scope.is_in_scope.side_effect = lambda url: "example.com" in url
    filtered = recon_module._filter_in_scope(["a.example.com", "evil.com"])
    assert filtered == ["a.example.com"]


@pytest.mark.asyncio
async def test_execute_runs_url_harvesting_before_live_hosts(recon_module):
    """URL harvesting must run before live host validation."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_acq():
        call_order.append("acquisition_discovery")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq):
            with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
                with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                    with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                        with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                            await recon_module.execute()

    assert call_order.index("url_harvesting") < call_order.index("live_host_validation")


@pytest.mark.asyncio
async def test_url_harvesting_parses_into_three_buckets(recon_module):
    """URL harvesting splits output: hostnames -> subdomains, paths -> endpoints, queries -> parameters."""
    gau_output = [
        "https://api.example.com/v1/users?id=123",
        "https://app.example.com/docs",
        "https://example.com",
    ]
    with patch.object(recon_module, '_run_gau', new_callable=AsyncMock, return_value=gau_output):
        with patch.object(recon_module, '_run_wayback', new_callable=AsyncMock, return_value=[]):
            await recon_module._url_harvesting()

    # Collect all enrich calls by key
    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        values = call.args[1]
        enrich_calls.setdefault(key, []).extend(values)

    # Hostnames go to discovered_subdomains
    assert "api.example.com" in enrich_calls.get("discovered_subdomains", [])
    assert "app.example.com" in enrich_calls.get("discovered_subdomains", [])
    assert "example.com" in enrich_calls.get("discovered_subdomains", [])
    # URL with query -> base path in endpoints, full in parameters
    assert "api.example.com/v1/users" in enrich_calls.get("endpoints", [])
    assert "api.example.com/v1/users?id=123" in enrich_calls.get("parameters", [])
    # URL with path no query -> endpoints
    assert "app.example.com/docs" in enrich_calls.get("endpoints", [])


@pytest.mark.asyncio
async def test_live_host_validation_includes_in_scope_urls(recon_module):
    """Live host validation probes discovered_subdomains + in_scope_urls."""
    recon_module.state.get.side_effect = lambda key: {
        "discovered_subdomains": ["app.example.com"],
    }.get(key, [])
    recon_module.config.in_scope_urls = ["partner.com", "extra.example.com"]

    probed_hosts = []

    async def mock_httpx(subdomains):
        probed_hosts.extend(subdomains)
        return [], []

    with patch.object(recon_module, '_run_httpx', side_effect=mock_httpx):
        await recon_module._live_host_validation()

    assert "app.example.com" in probed_hosts
    assert "partner.com" in probed_hosts
    assert "extra.example.com" in probed_hosts


def test_parse_amass_org_output_matches_company(recon_module):
    """Lines containing the company name (case-insensitive substring) are matched."""
    stdout = (
        "AS394161, 12.0.0.0/8, Tesla, Inc.\n"
        "AS12345, 10.0.0.0/16, Tesla Motors\n"
        "AS99999, 172.16.0.0/12, Unrelated Corp\n"
    )
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    asns = [r["asn"] for r in results]
    assert "AS394161" in asns
    assert "AS12345" in asns
    assert "AS99999" not in asns


def test_parse_amass_org_output_collects_cidrs(recon_module):
    """CIDRs present on matching lines are collected."""
    stdout = "AS394161, 12.0.0.0/8, Tesla, Inc.\n"
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    assert results[0]["cidr"] == "12.0.0.0/8"


def test_parse_amass_org_output_missing_cidr(recon_module):
    """Lines without a CIDR still return the ASN with cidr=None."""
    stdout = "AS394161 -- Tesla, Inc.\n"
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    assert results[0]["asn"] == "AS394161"
    assert results[0]["cidr"] is None


def test_parse_amass_org_output_empty_input(recon_module):
    """Empty or whitespace-only input returns empty list."""
    assert recon_module._parse_amass_org_output("", "Tesla") == []
    assert recon_module._parse_amass_org_output("  \n\n  ", "Tesla") == []


def test_parse_amass_org_output_no_asn_token(recon_module):
    """Lines without an AS\\d+ token are skipped."""
    stdout = "Some random line, Tesla\n"
    assert recon_module._parse_amass_org_output(stdout, "Tesla") == []


def test_parse_whois_radb_output_extracts_routes(recon_module):
    """Extracts CIDR from route: and route6: lines."""
    stdout = (
        "route:          12.0.0.0/8\n"
        "descr:          Tesla\n"
        "origin:         AS394161\n"
        "route6:         2001:db8::/32\n"
        "descr:          Tesla IPv6\n"
    )
    cidrs = recon_module._parse_whois_radb_output(stdout)
    assert "12.0.0.0/8" in cidrs
    assert "2001:db8::/32" in cidrs


def test_parse_whois_radb_output_empty(recon_module):
    assert recon_module._parse_whois_radb_output("") == []


def test_parse_whois_radb_output_no_routes(recon_module):
    stdout = "descr: Some description\norigin: AS12345\n"
    assert recon_module._parse_whois_radb_output(stdout) == []


@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="y")
@patch("subprocess.run")
def test_prompt_install_tool_accepted(mock_run, mock_input, recon_module):
    """When user accepts, install command runs and returns True."""
    mock_run.return_value = MagicMock(returncode=0)
    result = recon_module._prompt_install_tool("amass", "go install -v github.com/owasp-amass/amass/v4/...@master")
    assert result is True
    mock_run.assert_called_once()


@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="n")
def test_prompt_install_tool_declined(mock_input, recon_module):
    """When user declines, returns False without running install."""
    result = recon_module._prompt_install_tool("amass", "go install -v github.com/owasp-amass/amass/v4/...@master")
    assert result is False


@pytest.mark.asyncio
async def test_run_amass_intel_org_success(recon_module):
    """Successful amass intel -org returns parsed results."""
    mock_result = MagicMock()
    mock_result.tool_missing = False
    mock_result.returncode = 0
    mock_result.stdout = "AS394161, 12.0.0.0/8, Tesla, Inc.\n"

    recon_module.config.company_name = "Tesla"
    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        result = await recon_module._run_amass_intel_org("Tesla")
    assert result.stdout == mock_result.stdout


@pytest.mark.asyncio
async def test_run_amass_intel_org_missing_prompts_install(recon_module):
    """When amass is missing, prompts to install."""
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    success = MagicMock(tool_missing=False, returncode=0, stdout="AS1, 10.0.0.0/8, Tesla\n", stderr="")

    recon_module.config.company_name = "Tesla"
    with patch.object(recon_module._cmd, 'run', side_effect=[missing, success]):
        with patch.object(recon_module, '_prompt_install_tool', return_value=True):
            result = await recon_module._run_amass_intel_org("Tesla")
    assert result.returncode == 0


@pytest.mark.asyncio
async def test_run_amass_intel_asn_success(recon_module):
    """Successful amass intel -asn returns CommandResult."""
    mock_result = MagicMock()
    mock_result.tool_missing = False
    mock_result.returncode = 0
    mock_result.stdout = "12.0.0.0/8\n10.0.0.0/16\n"

    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        result = await recon_module._run_amass_intel_asn("AS394161")
    assert result.stdout == mock_result.stdout


@pytest.mark.asyncio
async def test_run_whois_radb_success(recon_module):
    """whois RADB returns route lines."""
    mock_result = MagicMock()
    mock_result.tool_missing = False
    mock_result.returncode = 0
    mock_result.stdout = "route:          12.0.0.0/8\norigin:         AS394161\n"

    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        result = await recon_module._run_whois_radb("AS394161")
    assert result.returncode == 0


@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_uses_amass_first(recon_module):
    """Uses amass intel -asn for IP ranges when available."""
    amass_result = MagicMock(returncode=0, stdout="12.0.0.0/8\n10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, return_value=amass_result):
        with patch.object(recon_module, '_run_whois_radb', new_callable=AsyncMock) as mock_whois:
            ranges = await recon_module._lookup_asn_ip_ranges(["AS394161"])
    assert "12.0.0.0/8" in ranges
    assert "10.0.0.0/16" in ranges
    mock_whois.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_falls_back_to_whois(recon_module):
    """Falls back to whois when amass returns nothing."""
    amass_result = MagicMock(returncode=1, stdout="", tool_missing=False)
    whois_result = MagicMock(returncode=0, stdout="route:          10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, return_value=amass_result):
        with patch.object(recon_module, '_run_whois_radb', new_callable=AsyncMock, return_value=whois_result):
            ranges = await recon_module._lookup_asn_ip_ranges(["AS12345"])
    assert "10.0.0.0/16" in ranges


@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_deduplicates(recon_module):
    """Duplicate CIDRs across ASNs are deduplicated."""
    result1 = MagicMock(returncode=0, stdout="10.0.0.0/16\n12.0.0.0/8\n", tool_missing=False)
    result2 = MagicMock(returncode=0, stdout="10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, side_effect=[result1, result2]):
        ranges = await recon_module._lookup_asn_ip_ranges(["AS1", "AS2"])
    assert ranges.count("10.0.0.0/16") == 1


@pytest.mark.asyncio
async def test_run_whois_radb_missing_prompts_install(recon_module):
    """When whois is missing, prompts to install."""
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    success = MagicMock(tool_missing=False, returncode=0, stdout="route: 10.0.0.0/8\n", stderr="")

    with patch.object(recon_module._cmd, 'run', side_effect=[missing, success]):
        with patch.object(recon_module, '_prompt_install_tool', return_value=True):
            result = await recon_module._run_whois_radb("AS12345")
    assert result.returncode == 0


def test_subcategories_includes_asn_enumeration(recon_module):
    """asn_enumeration is the first subcategory."""
    assert recon_module.SUBCATEGORIES[0] == "asn_enumeration"


@pytest.mark.asyncio
async def test_asn_enumeration_full_flow(recon_module):
    """Full ASN enumeration: amass org -> parse -> lookup ranges -> enrich state."""
    org_result = MagicMock(
        returncode=0, tool_missing=False,
        stdout="AS394161, 12.0.0.0/8, Tesla, Inc.\nAS99999, 172.16.0.0/12, Unrelated Corp\n",
    )
    recon_module.config.company_name = "Tesla"

    with patch.object(recon_module, '_run_amass_intel_org', new_callable=AsyncMock, return_value=org_result):
        with patch.object(recon_module, '_lookup_asn_ip_ranges', new_callable=AsyncMock, return_value=["12.0.0.0/8", "10.0.0.0/16"]):
            await recon_module._asn_enumeration()

    # Check state.enrich was called with ASNs and IP ranges
    enrich_calls = {call.args[0]: call.args[1] for call in recon_module.state.enrich.call_args_list}
    assert "AS394161" in enrich_calls["asns"]
    assert "AS99999" not in enrich_calls["asns"]
    assert "12.0.0.0/8" in enrich_calls["ip_ranges"]
    assert "10.0.0.0/16" in enrich_calls["ip_ranges"]


@pytest.mark.asyncio
async def test_asn_enumeration_includes_inline_cidrs(recon_module):
    """CIDRs found inline in amass org output are included in ip_ranges."""
    org_result = MagicMock(
        returncode=0, tool_missing=False,
        stdout="AS394161, 12.0.0.0/8, Tesla, Inc.\n",
    )
    recon_module.config.company_name = "Tesla"

    with patch.object(recon_module, '_run_amass_intel_org', new_callable=AsyncMock, return_value=org_result):
        with patch.object(recon_module, '_lookup_asn_ip_ranges', new_callable=AsyncMock, return_value=["10.0.0.0/16"]):
            await recon_module._asn_enumeration()

    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])
    # Both inline CIDR and looked-up CIDR should be present
    assert "12.0.0.0/8" in enrich_calls["ip_ranges"]
    assert "10.0.0.0/16" in enrich_calls["ip_ranges"]


@pytest.mark.asyncio
async def test_execute_runs_asn_enumeration_first(recon_module):
    """asn_enumeration runs before passive_osint in execute()."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_acq():
        call_order.append("acquisition_discovery")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq):
            with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
                with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                    with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                        with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                            await recon_module.execute()

    assert call_order[0] == "asn_enumeration"
    assert call_order[1] == "acquisition_discovery"
    assert call_order[2] == "passive_osint"


@pytest.mark.asyncio
async def test_asn_enumeration_skipped_when_amass_missing_and_declined(recon_module):
    """When amass is missing and user declines install, no ASNs are enriched."""
    missing_result = MagicMock(returncode=1, tool_missing=True, stdout="", stderr="")
    recon_module.config.company_name = "Tesla"

    with patch.object(recon_module, '_run_amass_intel_org', new_callable=AsyncMock, return_value=missing_result):
        await recon_module._asn_enumeration()

    # enrich should not have been called for asns
    asn_calls = [c for c in recon_module.state.enrich.call_args_list if c.args[0] == "asns"]
    assert len(asn_calls) == 0 or asn_calls[0].args[1] == []


@pytest.mark.asyncio
async def test_asn_enumeration_skips_without_company_name(recon_module):
    """ASN enumeration is skipped when company_name is empty."""
    recon_module.config.company_name = ""
    await recon_module._asn_enumeration()
    assert recon_module.state.enrich.call_count == 0


def test_parse_amass_org_output_ipv6_cidr(recon_module):
    """IPv6 CIDRs in amass org output are captured."""
    stdout = "AS394161, 2001:db8::/32, Tesla, Inc.\n"
    results = recon_module._parse_amass_org_output(stdout, "Tesla")
    assert results[0]["cidr"] == "2001:db8::/32"


@pytest.mark.asyncio
async def test_lookup_asn_ip_ranges_ipv6(recon_module):
    """IPv6 CIDRs from amass intel -asn are captured."""
    amass_result = MagicMock(returncode=0, stdout="2001:db8::/32\n10.0.0.0/16\n", tool_missing=False)

    with patch.object(recon_module, '_run_amass_intel_asn', new_callable=AsyncMock, return_value=amass_result):
        ranges = await recon_module._lookup_asn_ip_ranges(["AS1"])
    assert "2001:db8::/32" in ranges
    assert "10.0.0.0/16" in ranges


def test_parse_wikipedia_acquisitions_extracts_table_rows(recon_module):
    """Parses wiki table rows containing company name, domain, and year."""
    wikitext = (
        "== Acquisitions ==\n"
        "{| class=\"wikitable\"\n"
        "|-\n"
        "! Company !! Date !! Notes\n"
        "|-\n"
        "| [https://instagram.com Instagram] || October 2012 || Photo sharing\n"
        "|-\n"
        "| [https://whatsapp.com WhatsApp] || February 2014 || Messaging\n"
        "|-\n"
        "| Onavo || 2013 || VPN app\n"
        "|}\n"
    )
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    domains = [r["domain"] for r in results]
    companies = [r["company"] for r in results]
    assert "instagram.com" in domains
    assert "whatsapp.com" in domains
    assert "Instagram" in companies
    assert "WhatsApp" in companies
    # Onavo has no URL in the wikitext, so no domain extracted
    assert all(d != "" for d in domains)


def test_parse_wikipedia_acquisitions_no_section(recon_module):
    """Returns empty list when no acquisitions section exists."""
    wikitext = "== History ==\nFounded in 2004.\n== Products ==\nSome products.\n"
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    assert results == []


def test_parse_wikipedia_acquisitions_empty_table(recon_module):
    """Returns empty list when acquisitions section has no table rows with URLs."""
    wikitext = (
        "== Acquisitions ==\n"
        "The company has made several acquisitions.\n"
    )
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    assert results == []


def test_parse_wikipedia_acquisitions_list_page_format(recon_module):
    """Handles 'List of mergers and acquisitions by X' page format with external links."""
    wikitext = (
        "== List of acquisitions ==\n"
        "{| class=\"wikitable\"\n"
        "|-\n"
        "| [https://youtube.com YouTube] || October 2006 || $1.65B\n"
        "|}\n"
    )
    results = recon_module._parse_wikipedia_acquisitions(wikitext)
    assert len(results) >= 1
    assert results[0]["domain"] == "youtube.com"
    assert results[0]["company"] == "YouTube"


@pytest.mark.asyncio
async def test_fetch_wikipedia_acquisitions_success(recon_module):
    """Successful Wikipedia API call returns parsed acquisitions."""
    mock_response_data = {
        "parse": {
            "wikitext": {
                "*": (
                    "== Acquisitions ==\n"
                    "{| class=\"wikitable\"\n"
                    "|-\n"
                    "| [https://instagram.com Instagram] || 2012 || Photo sharing\n"
                    "|}\n"
                )
            }
        }
    }
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=mock_response_data)
        mock_session.get = AsyncMock(return_value=mock_resp)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        results = await recon_module._fetch_wikipedia_acquisitions("Meta")
    assert len(results) >= 1
    assert results[0]["source"] == "wikipedia"


@pytest.mark.asyncio
async def test_fetch_wikipedia_acquisitions_no_page(recon_module):
    """Returns empty list when Wikipedia page doesn't exist."""
    mock_response_data = {"error": {"code": "missingtitle"}}
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=mock_response_data)
        mock_session.get = AsyncMock(return_value=mock_resp)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        results = await recon_module._fetch_wikipedia_acquisitions("NonexistentCorp12345")
    assert results == []


@pytest.mark.asyncio
async def test_fetch_wikipedia_acquisitions_tries_list_page(recon_module):
    """Falls back to 'List of mergers and acquisitions by X' page."""
    no_acq_response = {
        "parse": {"wikitext": {"*": "== History ==\nFounded in 2004.\n"}}
    }
    list_response = {
        "parse": {
            "wikitext": {
                "*": (
                    "== Acquisitions ==\n"
                    "{| class=\"wikitable\"\n"
                    "|-\n"
                    "| [https://youtube.com YouTube] || 2006 || $1.65B\n"
                    "|}\n"
                )
            }
        }
    }

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        resp = AsyncMock()
        resp.status = 200
        if call_count == 0:
            resp.json = AsyncMock(return_value=no_acq_response)
        else:
            resp.json = AsyncMock(return_value=list_response)
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        call_count += 1
        return resp

    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_session.get = mock_get

        results = await recon_module._fetch_wikipedia_acquisitions("Alphabet")
    assert len(results) >= 1
    assert results[0]["domain"] == "youtube.com"


@pytest.mark.asyncio
async def test_fetch_crunchbase_acquisitions_success(recon_module):
    """Extracts acquisitions from Crunchbase via Playwright MCP tools."""
    search_snapshot = (
        "- link: Organization result\n"
        "  url: /organization/meta-platforms\n"
        "  text: Meta Platforms\n"
    )
    acq_snapshot = (
        "- row: Instagram | instagram.com | October 2012\n"
        "- row: WhatsApp | whatsapp.com | February 2014\n"
        "- row: Oculus VR | oculus.com | March 2014\n"
    )

    async def mock_mcp_call(tool_name, **kwargs):
        if tool_name == "browser_navigate":
            return {"success": True}
        if tool_name == "browser_snapshot":
            if not hasattr(mock_mcp_call, '_snapshot_count'):
                mock_mcp_call._snapshot_count = 0
            mock_mcp_call._snapshot_count += 1
            if mock_mcp_call._snapshot_count <= 2:
                return {"content": search_snapshot}
            return {"content": acq_snapshot}
        if tool_name == "browser_click":
            return {"success": True}
        if tool_name == "browser_close":
            return {"success": True}
        return {}

    with patch.object(recon_module, '_call_playwright_mcp', side_effect=mock_mcp_call):
        results = await recon_module._fetch_crunchbase_acquisitions("Meta")

    domains = [r["domain"] for r in results]
    assert "instagram.com" in domains
    assert "whatsapp.com" in domains
    assert all(r["source"] == "crunchbase" for r in results)


@pytest.mark.asyncio
async def test_fetch_crunchbase_acquisitions_playwright_unavailable(recon_module):
    """Returns empty list when Playwright MCP is not available."""
    async def mock_mcp_call(tool_name, **kwargs):
        raise RuntimeError("MCP server not configured")

    with patch.object(recon_module, '_call_playwright_mcp', side_effect=mock_mcp_call):
        results = await recon_module._fetch_crunchbase_acquisitions("Meta")

    assert results == []


@pytest.mark.asyncio
async def test_fetch_crunchbase_acquisitions_no_results(recon_module):
    """Returns empty list when Crunchbase has no acquisition data."""
    async def mock_mcp_call(tool_name, **kwargs):
        if tool_name == "browser_navigate":
            return {"success": True}
        if tool_name == "browser_snapshot":
            return {"content": "No acquisitions found."}
        if tool_name == "browser_click":
            return {"success": True}
        if tool_name == "browser_close":
            return {"success": True}
        return {}

    with patch.object(recon_module, '_call_playwright_mcp', side_effect=mock_mcp_call):
        results = await recon_module._fetch_crunchbase_acquisitions("TinyStartup")

    assert results == []


def test_subcategories_includes_acquisition_discovery(recon_module):
    """acquisition_discovery is the second subcategory (after asn_enumeration)."""
    assert "acquisition_discovery" in recon_module.SUBCATEGORIES
    assert recon_module.SUBCATEGORIES.index("acquisition_discovery") == 1
    assert recon_module.SUBCATEGORIES.index("acquisition_discovery") < recon_module.SUBCATEGORIES.index("passive_osint")


@pytest.mark.asyncio
async def test_acquisition_discovery_enriches_state(recon_module):
    """Full flow: Wikipedia returns acquisitions, state and scope are updated."""
    recon_module.config.company_name = "Meta"
    recon_module.config.auto_expand_scope = True
    recon_module.config.config_path = "/tmp/test_config.yaml"

    wiki_results = [
        {"company": "Instagram", "domain": "instagram.com", "year": "2012", "source": "wikipedia"},
        {"company": "WhatsApp", "domain": "whatsapp.com", "year": "2014", "source": "wikipedia"},
    ]
    with patch.object(recon_module, '_fetch_wikipedia_acquisitions', new_callable=AsyncMock, return_value=wiki_results):
        await recon_module._acquisition_discovery()

    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])

    assert "instagram.com" in enrich_calls.get("discovered_subdomains", [])
    assert "whatsapp.com" in enrich_calls.get("discovered_subdomains", [])
    assert any(a["company"] == "Instagram" for a in enrich_calls.get("acquired_companies", []))

    recon_module.scope.add_in_scope_hostnames.assert_called_once_with(["instagram.com", "whatsapp.com"])
    recon_module.config.append_in_scope_urls.assert_called_once_with(["instagram.com", "whatsapp.com"])


@pytest.mark.asyncio
async def test_acquisition_discovery_falls_back_to_crunchbase(recon_module):
    """When Wikipedia returns nothing, Crunchbase fallback is tried."""
    recon_module.config.company_name = "SmallCorp"
    recon_module.config.auto_expand_scope = True
    recon_module.config.config_path = "/tmp/test_config.yaml"

    cb_results = [
        {"company": "AcquiredCo", "domain": "acquiredco.com", "year": "2023", "source": "crunchbase"},
    ]
    with patch.object(recon_module, '_fetch_wikipedia_acquisitions', new_callable=AsyncMock, return_value=[]):
        with patch.object(recon_module, '_fetch_crunchbase_acquisitions', new_callable=AsyncMock, return_value=cb_results):
            await recon_module._acquisition_discovery()

    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])
    assert "acquiredco.com" in enrich_calls.get("discovered_subdomains", [])


@pytest.mark.asyncio
async def test_acquisition_discovery_skips_without_company_name(recon_module):
    """Skips when company_name is empty."""
    recon_module.config.company_name = ""
    await recon_module._acquisition_discovery()
    assert recon_module.state.enrich.call_count == 0


@pytest.mark.asyncio
async def test_acquisition_discovery_respects_auto_expand_false(recon_module):
    """When auto_expand_scope is False, domains go to state but not scope."""
    recon_module.config.company_name = "Meta"
    recon_module.config.auto_expand_scope = False
    recon_module.config.config_path = "/tmp/test_config.yaml"

    wiki_results = [
        {"company": "Instagram", "domain": "instagram.com", "year": "2012", "source": "wikipedia"},
    ]
    with patch.object(recon_module, '_fetch_wikipedia_acquisitions', new_callable=AsyncMock, return_value=wiki_results):
        await recon_module._acquisition_discovery()

    enrich_calls = {}
    for call in recon_module.state.enrich.call_args_list:
        key = call.args[0]
        enrich_calls.setdefault(key, []).extend(call.args[1])
    assert "instagram.com" in enrich_calls.get("discovered_subdomains", [])

    recon_module.scope.add_in_scope_hostnames.assert_not_called()
    recon_module.config.append_in_scope_urls.assert_not_called()


@pytest.mark.asyncio
async def test_execute_runs_acquisition_discovery_after_asn(recon_module):
    """acquisition_discovery runs after asn_enumeration, before passive_osint."""
    call_order = []

    async def mock_asn():
        call_order.append("asn_enumeration")

    async def mock_acq():
        call_order.append("acquisition_discovery")

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_asn_enumeration', side_effect=mock_asn):
        with patch.object(recon_module, '_acquisition_discovery', side_effect=mock_acq):
            with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
                with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
                    with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                        with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                            await recon_module.execute()

    assert call_order[0] == "asn_enumeration"
    assert call_order[1] == "acquisition_discovery"
    assert call_order[2] == "passive_osint"
