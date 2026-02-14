# tests/test_session_testing.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.session_testing import SessionTestingModule


@pytest.fixture
def session_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "auth_endpoints": ["https://app.example.com/login"],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    config.get_auth_profile.return_value = None
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return SessionTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(session_module):
    assert session_module.PHASE_NAME == "session_testing"


def test_subcategories(session_module):
    assert "cookie_flags" in session_module.SUBCATEGORIES
    assert "session_fixation" in session_module.SUBCATEGORIES
    assert "session_lifecycle" in session_module.SUBCATEGORIES


def test_analyze_cookie_flags(session_module):
    cookie_header = "session=abc123; Path=/; HttpOnly"
    result = session_module._analyze_cookie_flags("session", cookie_header)
    assert result["httponly"] is True
    assert result["secure"] is False
    assert result["samesite"] is None


def test_analyze_cookie_flags_all_set(session_module):
    cookie_header = "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
    result = session_module._analyze_cookie_flags("session", cookie_header)
    assert result["httponly"] is True
    assert result["secure"] is True
    assert result["samesite"] == "Strict"