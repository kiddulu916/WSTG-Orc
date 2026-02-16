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
            "wildcard_urls": ["testcorp.com"],
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


def test_enumeration_domains(config_file):
    config = ConfigLoader(config_file)
    domains = config.enumeration_domains
    assert domains[0] == "testcorp.com"
    # in_scope_urls should NOT be in enumeration_domains
    assert "app.testcorp.com" not in domains
    assert "api.testcorp.com" not in domains


def test_enumeration_domains_deduplicates():
    cfg = {
        "program_scope": {
            "base_domain": "testcorp.com",
            "wildcard_urls": ["testcorp.com", "testcorp.com"],
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        domains = config.enumeration_domains
        assert domains.count("testcorp.com") == 1
    finally:
        os.remove(path)


def test_enumeration_domains_excludes_in_scope_urls():
    """enumeration_domains should only combine base_domain + wildcard_urls, NOT in_scope_urls."""
    cfg = {
        "program_scope": {
            "base_domain": "testcorp.com",
            "wildcard_urls": ["testcorp.com", "api.testcorp.com"],
            "in_scope_urls": ["partner.com", "app.testcorp.com/dashboard"],
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        domains = config.enumeration_domains
        assert "testcorp.com" in domains
        assert "api.testcorp.com" in domains
        assert "partner.com" not in domains
        assert "app.testcorp.com" not in domains
    finally:
        os.remove(path)


def test_scope_checker_uses_wildcard_and_in_scope():
    cfg = {
        "program_scope": {
            "base_domain": "testcorp.com",
            "wildcard_urls": ["testcorp.com"],
            "in_scope_urls": ["partner.com"],
            "out_of_scope_urls": [],
            "out_of_scope_ips": [],
            "out_of_scope_attack_vectors": [],
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        checker = config.create_scope_checker()
        assert checker.is_in_scope("partner.com") is True
        assert checker.is_in_scope("evil.com") is False
    finally:
        os.remove(path)


def test_auto_expand_scope_defaults_true(config_file):
    """auto_expand_scope defaults to True when not set in config."""
    config = ConfigLoader(config_file)
    assert config.auto_expand_scope is True


def test_auto_expand_scope_reads_from_config():
    """auto_expand_scope reads from program_scope when explicitly set."""
    cfg = {
        "program_scope": {
            "base_domain": "test.com",
            "auto_expand_scope": False,
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        assert config.auto_expand_scope is False
    finally:
        os.remove(path)


def test_config_path_stored(config_file):
    """ConfigLoader stores the config file path."""
    config = ConfigLoader(config_file)
    assert config.config_path == config_file


def test_append_in_scope_urls_adds_to_memory(config_file):
    """append_in_scope_urls updates in-memory in_scope_urls."""
    config = ConfigLoader(config_file)
    config.append_in_scope_urls(["newdomain.com", "another.com"])
    assert "newdomain.com" in config.in_scope_urls
    assert "another.com" in config.in_scope_urls


def test_append_in_scope_urls_persists_to_yaml(config_file):
    """append_in_scope_urls writes changes to the YAML file on disk."""
    config = ConfigLoader(config_file)
    original_count = len(config.in_scope_urls)
    config.append_in_scope_urls(["persisted.com"])

    # Reload from disk
    reloaded = ConfigLoader(config_file)
    assert "persisted.com" in reloaded.in_scope_urls
    assert len(reloaded.in_scope_urls) == original_count + 1


def test_append_in_scope_urls_deduplicates(config_file):
    """Already present URLs are not duplicated."""
    config = ConfigLoader(config_file)
    existing = list(config.in_scope_urls)
    config.append_in_scope_urls([existing[0], "brand-new.com"])
    assert config.in_scope_urls.count(existing[0]) == 1
    assert "brand-new.com" in config.in_scope_urls


def test_append_in_scope_urls_empty_list(config_file):
    """Appending empty list is a no-op."""
    config = ConfigLoader(config_file)
    before = list(config.in_scope_urls)
    config.append_in_scope_urls([])
    assert config.in_scope_urls == before


# --- update_tool_config tests ---


@pytest.fixture
def minimal_config_file(tmp_path):
    config = {
        "program_scope": {"base_domain": "example.com"},
        "tool_configs": {"subfinder": {"extra_args": ["-all"]}},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))
    return str(path)


def test_update_tool_config_adds_new_key(minimal_config_file):
    loader = ConfigLoader(minimal_config_file)
    loader.update_tool_config("github_subdomains", "token", "ghp_abc123")

    # Verify in-memory
    assert loader.get_tool_config("github_subdomains")["token"] == "ghp_abc123"

    # Verify on disk
    with open(minimal_config_file) as f:
        raw = yaml.safe_load(f)
    assert raw["tool_configs"]["github_subdomains"]["token"] == "ghp_abc123"


def test_update_tool_config_preserves_existing(minimal_config_file):
    loader = ConfigLoader(minimal_config_file)
    loader.update_tool_config("github_subdomains", "token", "ghp_abc123")

    # subfinder config should still be there
    assert loader.get_tool_config("subfinder")["extra_args"] == ["-all"]


def test_update_tool_config_creates_tool_configs_section(tmp_path):
    config = {"program_scope": {"base_domain": "example.com"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))

    loader = ConfigLoader(str(path))
    loader.update_tool_config("gitlab_subdomains", "token", "glpat_xyz")
    assert loader.get_tool_config("gitlab_subdomains")["token"] == "glpat_xyz"
