import os
import sys
import tempfile
import pytest
import yaml

# main.py lives at repo root, not inside the wstg_orchestrator package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
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
