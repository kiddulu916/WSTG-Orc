# tests/test_configuration_testing.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.configuration_testing import ConfigTestingModule


@pytest.fixture
def config_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "endpoints": [],
        "exposed_admin_paths": [],
        "cloud_assets": [],
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
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_request.return_value = "/tmp/test"
    evidence.log_response.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return ConfigTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(config_module):
    assert config_module.PHASE_NAME == "configuration_testing"


def test_subcategories(config_module):
    assert "metafile_testing" in config_module.SUBCATEGORIES
    assert "http_method_testing" in config_module.SUBCATEGORIES
    assert "cloud_storage_enum" in config_module.SUBCATEGORIES


def test_parse_robots_txt(config_module):
    robots = "User-agent: *\nDisallow: /admin/\nDisallow: /secret/\nAllow: /public/"
    paths = config_module._parse_robots_txt(robots)
    assert "/admin/" in paths
    assert "/secret/" in paths


def test_detect_cloud_patterns(config_module):
    urls = [
        "https://mybucket.s3.amazonaws.com/file",
        "https://storage.googleapis.com/mybucket/file",
        "https://myaccount.blob.core.windows.net/container/file",
        "https://normal.example.com/page",
    ]
    cloud = config_module._detect_cloud_patterns(urls)
    assert len(cloud) == 3
    assert any(c["provider"] == "aws_s3" for c in cloud)
    assert any(c["provider"] == "gcs" for c in cloud)
    assert any(c["provider"] == "azure_blob" for c in cloud)