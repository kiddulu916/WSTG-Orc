# tests/test_main.py
import asyncio
import os
import tempfile
import pytest
import yaml
from unittest.mock import patch, MagicMock, AsyncMock
from main import Orchestrator


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def config_file(tmp_dir):
    config = {
        "program_scope": {
            "company_name": "TestCorp",
            "base_domain": "testcorp.com",
            "wildcard_urls": ["*.testcorp.com"],
            "in_scope_urls": [],
            "in_scope_ips": [],
            "out_of_scope_urls": [],
            "out_of_scope_ips": [],
            "out_of_scope_attack_vectors": [],
            "rate_limit": 50,
            "custom_headers": {},
            "notes": "",
        },
        "auth_profiles": {},
        "tool_configs": {},
        "callback_server": {"host": "127.0.0.1", "port": 0},
    }
    path = os.path.join(tmp_dir, "config.yaml")
    with open(path, "w") as f:
        yaml.dump(config, f)
    return path


def test_orchestrator_init(config_file, tmp_dir):
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    assert orch.config.company_name == "TestCorp"
    assert orch.state.get("target_domain") == "testcorp.com"


def test_orchestrator_creates_evidence_dir(config_file, tmp_dir):
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    assert os.path.isdir(os.path.join(tmp_dir, "evidence", "TestCorp"))


def test_orchestrator_module_order(config_file, tmp_dir):
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    order = orch.get_execution_order()
    assert order[0] == "reconnaissance"
    assert "fingerprinting" in order
    assert order.index("reconnaissance") < order.index("input_validation")


def test_orchestrator_run_checks_pause(config_file, tmp_dir):
    """Orchestrator.run() checks signal_handler pause state between phases."""
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    signal_handler = MagicMock()
    signal_handler.is_paused.return_value = False

    mock_module = MagicMock()
    mock_module.run = AsyncMock()
    orch.register_module("reconnaissance", mock_module)

    with patch.object(orch, '_check_tools'):
        with patch.object(orch.callback_server, 'start'):
            with patch.object(orch.callback_server, 'stop'):
                asyncio.run(orch.run(signal_handler=signal_handler))

    signal_handler.is_paused.assert_called()


def test_orchestrator_run_without_signal_handler(config_file, tmp_dir):
    """Orchestrator.run() works without a signal_handler (backwards compat)."""
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    mock_module = MagicMock()
    mock_module.run = AsyncMock()
    orch.register_module("reconnaissance", mock_module)

    with patch.object(orch, '_check_tools'):
        with patch.object(orch.callback_server, 'start'):
            with patch.object(orch.callback_server, 'stop'):
                asyncio.run(orch.run())
    mock_module.run.assert_called_once()


def test_orchestrator_has_current_phase_and_skip(config_file, tmp_dir):
    """Orchestrator has current_phase and _skip_phase attributes."""
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    assert orch.current_phase is None
    assert orch._skip_phase is False