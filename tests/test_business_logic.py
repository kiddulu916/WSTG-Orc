# tests/test_business_logic.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.business_logic import BusinessLogicModule


@pytest.fixture
def bl_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "endpoints": [
            "https://app.example.com/checkout",
            "https://app.example.com/api/order",
        ],
        "parameters": [
            {"url": "https://app.example.com/api/order", "name": "price", "value": "99.99", "method": "POST"},
            {"url": "https://app.example.com/api/order", "name": "quantity", "value": "1", "method": "POST"},
        ],
        "forms": [],
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
    callback = MagicMock()
    return BusinessLogicModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(bl_module):
    assert bl_module.PHASE_NAME == "business_logic"


def test_subcategories(bl_module):
    assert "workflow_bypass" in bl_module.SUBCATEGORIES
    assert "parameter_tampering" in bl_module.SUBCATEGORIES
    assert "race_conditions" in bl_module.SUBCATEGORIES


def test_tamper_values(bl_module):
    values = bl_module.PRICE_TAMPER_VALUES
    assert 0 in values
    assert -1 in values
    assert 0.01 in values


def test_race_skipped_when_dos_blocked():
    state = MagicMock()
    state.get.return_value = []
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    scope = MagicMock()
    scope.is_attack_vector_allowed.side_effect = lambda v: v != "dos"
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()
    mod = BusinessLogicModule(state, config, scope, limiter, evidence, callback)
    assert mod.is_attack_allowed("dos") is False