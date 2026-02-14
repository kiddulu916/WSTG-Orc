# tests/test_input_validation.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.input_validation import InputValidationModule


@pytest.fixture
def iv_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "parameters": [
            {"url": "https://app.example.com/search", "name": "q", "value": "test", "method": "GET"},
            {"url": "https://app.example.com/api/users", "name": "id", "value": "1", "method": "GET"},
        ],
        "live_hosts": ["https://app.example.com"],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    scope.is_attack_vector_allowed.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    callback.generate_callback.return_value = ("http://127.0.0.1:8443/abc123", "abc123")
    return InputValidationModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(iv_module):
    assert iv_module.PHASE_NAME == "input_validation"


def test_subcategories(iv_module):
    assert "sqli_testing" in iv_module.SUBCATEGORIES
    assert "xss_testing" in iv_module.SUBCATEGORIES
    assert "command_injection" in iv_module.SUBCATEGORIES


def test_sqli_payloads_exist(iv_module):
    assert len(iv_module.SQLI_ERROR_PAYLOADS) > 0
    assert "'" in iv_module.SQLI_ERROR_PAYLOADS


def test_xss_payloads_exist(iv_module):
    assert len(iv_module.XSS_PAYLOADS) > 0
    assert any("<script>" in p.lower() or "onerror" in p.lower() for p in iv_module.XSS_PAYLOADS)


def test_cmdi_payloads_exist(iv_module):
    assert len(iv_module.CMDI_PAYLOADS) > 0