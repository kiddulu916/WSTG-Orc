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
        "*.testcorp.com, *.api.testcorp.com",# wildcard urls
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
    assert config["program_scope"]["wildcard_urls"] == ["testcorp.com", "api.testcorp.com"]
    assert "app.testcorp.com" in config["program_scope"]["in_scope_urls"]
    assert "admin.testcorp.com" in config["program_scope"]["out_of_scope_urls"]
    assert "dos" in config["program_scope"]["out_of_scope_attack_vectors"]
    assert config["program_scope"]["rate_limit"] == 10
    assert config["program_scope"]["custom_headers"]["X-Bug-Bounty"] == "testcorp-123"


def test_build_config_wildcard_default_fallback():
    """When no wildcard URLs are provided, defaults to *.base_domain."""
    inputs = iter([
        "TestCorp",                          # company name
        "testcorp.com",                      # base domain
        "",                                  # wildcard urls (empty)
        "",                                  # in-scope urls
        "",                                  # in-scope ips
        "",                                  # out-of-scope urls
        "",                                  # out-of-scope ips
        "",                                  # out-of-scope attack vectors
        "",                                  # rate limit (default)
        "",                                  # custom headers
        "",                                  # auth profiles (skip)
        "",                                  # callback host (default)
        "",                                  # callback port (default)
        "",                                  # notes
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        builder = ScopeBuilder()
        config = builder.build()

    assert config["program_scope"]["wildcard_urls"] == ["testcorp.com"]


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


def test_build_strips_scheme_from_base_domain():
    inputs = iter([
        "TestCorp",
        "https://testcorp.com",  # base domain WITH scheme
        "", "", "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["base_domain"] == "testcorp.com"


def test_build_strips_scheme_and_wildcard_from_wildcard_urls():
    inputs = iter([
        "TestCorp", "testcorp.com",
        "https://*.testcorp.com, http://*.api.testcorp.com",
        "", "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["wildcard_urls"] == ["testcorp.com", "api.testcorp.com"]


def test_build_wildcard_default_stripped():
    inputs = iter([
        "TestCorp", "testcorp.com",
        "",  # empty -> default
        "", "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["wildcard_urls"] == ["testcorp.com"]


def test_build_strips_scheme_from_in_scope_urls():
    inputs = iter([
        "TestCorp", "testcorp.com", "",
        "https://app.testcorp.com/dashboard, http://partner.com",
        "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["in_scope_urls"] == [
        "app.testcorp.com/dashboard", "partner.com"
    ]


def test_build_strips_scheme_from_out_of_scope_urls():
    inputs = iter([
        "TestCorp", "testcorp.com", "", "", "",
        "https://admin.testcorp.com/panel, *.internal.testcorp.com",
        "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["out_of_scope_urls"] == [
        "admin.testcorp.com/panel", "*.internal.testcorp.com"
    ]