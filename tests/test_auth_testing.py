# tests/test_auth_testing.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.auth_testing import AuthTestingModule


@pytest.fixture
def auth_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "auth_endpoints": ["https://app.example.com/login"],
        "valid_usernames": [],
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
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_request.return_value = "/tmp/test"
    evidence.log_response.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return AuthTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(auth_module):
    assert auth_module.PHASE_NAME == "auth_testing"


def test_subcategories(auth_module):
    assert "username_enumeration" in auth_module.SUBCATEGORIES
    assert "default_credentials" in auth_module.SUBCATEGORIES
    assert "lockout_testing" in auth_module.SUBCATEGORIES


def test_default_credentials_list(auth_module):
    creds = auth_module.DEFAULT_CREDENTIALS
    assert ("admin", "admin") in creds
    assert ("root", "root") in creds


def test_detect_username_enum_by_response_diff(auth_module):
    resp_valid = MagicMock()
    resp_valid.text = "Invalid password for this account"
    resp_valid.status_code = 200
    resp_valid.elapsed = 0.2

    resp_invalid = MagicMock()
    resp_invalid.text = "User does not exist"
    resp_invalid.status_code = 200
    resp_invalid.elapsed = 0.2

    result = auth_module._detect_enum_by_diff(resp_valid, resp_invalid)
    assert result["enumerable"] is True
    assert result["method"] == "response_content"