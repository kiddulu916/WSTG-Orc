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

    async def mock_passive():
        call_order.append("passive_osint")

    async def mock_harvest():
        call_order.append("url_harvesting")

    async def mock_live():
        call_order.append("live_host_validation")

    async def mock_params():
        call_order.append("parameter_harvesting")

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
