# tests/test_authorization_testing.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.authorization_testing import AuthorizationTestingModule


@pytest.fixture
def authz_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "potential_idor_candidates": [
            {"url": "https://app.example.com/user/123", "type": "numeric", "value": "123"},
        ],
        "endpoints": ["https://app.example.com/api/profile"],
        "parameters": [],
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
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return AuthorizationTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(authz_module):
    assert authz_module.PHASE_NAME == "authorization_testing"


def test_subcategories(authz_module):
    assert "idor_testing" in authz_module.SUBCATEGORIES
    assert "privilege_escalation" in authz_module.SUBCATEGORIES
    assert "jwt_testing" in authz_module.SUBCATEGORIES


def test_generate_idor_candidates(authz_module):
    candidates = authz_module._generate_numeric_idor_values("123")
    assert 122 in candidates
    assert 124 in candidates
    assert 1 in candidates


def test_decode_jwt(authz_module):
    # HS256 JWT with {"sub":"1234567890","name":"Test","iat":1516239022}
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = authz_module._decode_jwt(token)
    assert result is not None
    assert result["header"]["alg"] == "HS256"
    assert result["payload"]["name"] == "Test"