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
    assert "live_host_validation" in recon_module.SUBCATEGORIES
    assert "parameter_harvesting" in recon_module.SUBCATEGORIES


@pytest.mark.asyncio
async def test_passive_osint_runs_subfinder(recon_module):
    with patch.object(recon_module, '_run_subfinder', new_callable=AsyncMock, return_value=["sub.example.com"]):
        with patch.object(recon_module, '_run_gau', new_callable=AsyncMock, return_value=[]):
            with patch.object(recon_module, '_run_wayback', new_callable=AsyncMock, return_value=[]):
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
        with patch.object(recon_module, '_run_gau', new_callable=AsyncMock, return_value=[]):
            with patch.object(recon_module, '_run_wayback', new_callable=AsyncMock, return_value=[]):
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