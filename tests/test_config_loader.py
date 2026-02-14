# tests/test_config_loader.py
import os
import tempfile
import pytest
import yaml
from wstg_orchestrator.utils.config_loader import ConfigLoader


@pytest.fixture
def sample_config():
    return {
        "program_scope": {
            "company_name": "TestCorp",
            "base_domain": "testcorp.com",
            "wildcard_urls": ["*.testcorp.com"],
            "in_scope_urls": ["app.testcorp.com", "api.testcorp.com"],
            "in_scope_ips": [],
            "out_of_scope_urls": ["admin.testcorp.com"],
            "out_of_scope_ips": ["10.0.0.1"],
            "out_of_scope_attack_vectors": ["dos"],
            "rate_limit": 10,
            "custom_headers": {"X-Bug-Bounty": "testcorp-program"},
            "notes": "No destructive testing",
        },
        "auth_profiles": {
            "default": {
                "type": "bearer",
                "token": "abc123",
            }
        },
        "tool_configs": {
            "nmap": {"flags": "-T3"},
            "gobuster": {"threads": 20},
        },
        "callback_server": {
            "host": "0.0.0.0",
            "port": 8443,
        },
    }


@pytest.fixture
def config_file(sample_config):
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(sample_config, f)
    yield path
    os.remove(path)


def test_load_config(config_file):
    config = ConfigLoader(config_file)
    assert config.company_name == "TestCorp"
    assert config.base_domain == "testcorp.com"
    assert config.rate_limit == 10


def test_custom_headers(config_file):
    config = ConfigLoader(config_file)
    assert config.custom_headers == {"X-Bug-Bounty": "testcorp-program"}


def test_get_tool_config(config_file):
    config = ConfigLoader(config_file)
    nmap_cfg = config.get_tool_config("nmap")
    assert nmap_cfg["flags"] == "-T3"
    assert config.get_tool_config("unknown_tool") == {}


def test_auth_profile(config_file):
    config = ConfigLoader(config_file)
    profile = config.get_auth_profile("default")
    assert profile["type"] == "bearer"
    assert profile["token"] == "abc123"
    assert config.get_auth_profile("nonexistent") is None


def test_scope_checker_creation(config_file):
    config = ConfigLoader(config_file)
    checker = config.create_scope_checker()
    assert checker.is_in_scope("https://app.testcorp.com") is True
    assert checker.is_in_scope("https://admin.testcorp.com") is False


def test_callback_config(config_file):
    config = ConfigLoader(config_file)
    assert config.callback_host == "0.0.0.0"
    assert config.callback_port == 8443


def test_out_of_scope_attack_vectors(config_file):
    config = ConfigLoader(config_file)
    checker = config.create_scope_checker()
    assert checker.is_attack_vector_allowed("dos") is False
    assert checker.is_attack_vector_allowed("sqli") is True