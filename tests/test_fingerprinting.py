# tests/test_fingerprinting.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.fingerprinting import FingerprintingModule


@pytest.fixture
def fp_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "technologies": ["nginx"],
        "server_versions": [],
        "frameworks": [],
        "inferred_cves": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_request.return_value = "/tmp/test"
    evidence.log_response.return_value = "/tmp/test"
    callback = MagicMock()
    return FingerprintingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(fp_module):
    assert fp_module.PHASE_NAME == "fingerprinting"


def test_subcategories(fp_module):
    assert "service_scanning" in fp_module.SUBCATEGORIES
    assert "header_analysis" in fp_module.SUBCATEGORIES
    assert "cve_correlation" in fp_module.SUBCATEGORIES


@pytest.mark.asyncio
async def test_header_analysis_extracts_server(fp_module):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "Apache/2.4.51", "X-Powered-By": "PHP/8.1.0"}
    mock_resp.text = ""
    mock_resp.content = b""
    mock_resp.url = "https://app.example.com"
    mock_resp.elapsed = 0.5
    mock_resp.request_method = "GET"
    mock_resp.request_url = "https://app.example.com"
    mock_resp.request_headers = {}
    mock_resp.request_body = None

    with patch.object(fp_module, '_make_request', new_callable=AsyncMock, return_value=mock_resp):
        results = await fp_module._analyze_headers("https://app.example.com")
        assert any("Apache" in v for v in results["server_versions"])
        assert any("PHP" in v for v in results["frameworks"])


@pytest.mark.asyncio
async def test_nmap_parsing(fp_module):
    nmap_xml = '''<?xml version="1.0"?>
    <nmaprun>
        <host>
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https" product="nginx" version="1.21.0"/>
                </port>
            </ports>
        </host>
    </nmaprun>'''
    results = fp_module._parse_nmap_xml(nmap_xml)
    assert any(p["port"] == 443 for p in results["ports"])
    assert any("nginx" in v for v in results["server_versions"])