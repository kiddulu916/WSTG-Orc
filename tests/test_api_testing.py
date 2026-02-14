# tests/test_api_testing.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.api_testing import ApiTestingModule


@pytest.fixture
def api_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "endpoints": [
            "https://app.example.com/api/v1/users",
            "https://app.example.com/graphql",
        ],
        "api_endpoints": [],
        "parameters": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return ApiTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(api_module):
    assert api_module.PHASE_NAME == "api_testing"


def test_subcategories(api_module):
    assert "api_discovery" in api_module.SUBCATEGORIES
    assert "bola_testing" in api_module.SUBCATEGORIES
    assert "graphql_testing" in api_module.SUBCATEGORIES


def test_swagger_paths(api_module):
    assert len(api_module.SWAGGER_PATHS) > 0
    assert "/swagger.json" in api_module.SWAGGER_PATHS or "/openapi.json" in api_module.SWAGGER_PATHS


def test_graphql_introspection_query(api_module):
    query = api_module.INTROSPECTION_QUERY
    assert "__schema" in query
    assert "queryType" in query