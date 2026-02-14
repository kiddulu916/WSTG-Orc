# tests/test_scope_builder.py
import os
import tempfile
import pytest
import yaml
from unittest.mock import patch
from wstg_orchestrator.scope_builder import ScopeBuilder


def test_build_config_from_inputs():
    inputs = iter([
        "TestCorp",                          # company name
        "testcorp.com",                      # base domain
        "app.testcorp.com, api.testcorp.com",# in-scope urls
        "",                                  # in-scope ips
        "admin.testcorp.com",                # out-of-scope urls
        "10.0.0.1",                          # out-of-scope ips
        "dos, social_engineering",           # out-of-scope attack vectors
        "10",                                # rate limit
        "X-Bug-Bounty: testcorp-123",        # custom headers
        "",                                  # auth profiles (skip)
        "",                                  # callback host (default)
        "",                                  # callback port (default)
        "No destructive testing allowed",    # notes
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        builder = ScopeBuilder()
        config = builder.build()

    assert config["program_scope"]["company_name"] == "TestCorp"
    assert config["program_scope"]["base_domain"] == "testcorp.com"
    assert "app.testcorp.com" in config["program_scope"]["in_scope_urls"]
    assert "admin.testcorp.com" in config["program_scope"]["out_of_scope_urls"]
    assert "dos" in config["program_scope"]["out_of_scope_attack_vectors"]
    assert config["program_scope"]["rate_limit"] == 10
    assert config["program_scope"]["custom_headers"]["X-Bug-Bounty"] == "testcorp-123"


def test_save_config():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "config.yaml")
        config_data = {
            "program_scope": {"company_name": "Test", "base_domain": "test.com"},
        }
        ScopeBuilder.save_config(config_data, path)
        assert os.path.exists(path)
        with open(path) as f:
            loaded = yaml.safe_load(f)
        assert loaded["program_scope"]["company_name"] == "Test"