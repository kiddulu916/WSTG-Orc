import tempfile
import os
import pytest

from wstg_orchestrator.utils.config_loader import ConfigLoader


class TestConfigLoader:
    def test_load_basic_config(self):
        """Test loading basic configuration"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
rate_limit: 10
custom_headers:
  User-Agent: "WSTG-Scanner/1.0"
  X-Custom: "test"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)

            assert config.company_name == "TestCorp"
            assert config.base_domain == "example.com"
            assert config.rate_limit == 10
            assert config.custom_headers == {
                "User-Agent": "WSTG-Scanner/1.0",
                "X-Custom": "test"
            }
        finally:
            os.unlink(config_file)

    def test_load_scope_config(self):
        """Test loading scope configuration"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
wildcard_urls:
  - "*.example.com"
in_scope_urls:
  - "api.example.com"
  - "app.example.com"
in_scope_ips:
  - "192.168.1.0/24"
out_of_scope_urls:
  - "admin.example.com"
  - "*.internal.example.com"
out_of_scope_ips:
  - "192.168.1.100"
out_of_scope_attack_vectors:
  - "sqli"
  - "xss"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)

            assert config.wildcard_urls == ["*.example.com"]
            assert config.in_scope_urls == ["api.example.com", "app.example.com"]
            assert config.in_scope_ips == ["192.168.1.0/24"]
            assert config.out_of_scope_urls == ["admin.example.com", "*.internal.example.com"]
            assert config.out_of_scope_ips == ["192.168.1.100"]
            assert config.out_of_scope_attack_vectors == ["sqli", "xss"]
        finally:
            os.unlink(config_file)

    def test_load_callback_config(self):
        """Test loading callback configuration"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
callback_host: "callback.example.com"
callback_port: 8080
notes: "Test scan for development environment"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)

            assert config.callback_host == "callback.example.com"
            assert config.callback_port == 8080
            assert config.notes == "Test scan for development environment"
        finally:
            os.unlink(config_file)

    def test_get_tool_config(self):
        """Test getting tool-specific configuration"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
tools:
  nmap:
    extra_args: ["-T4", "-A"]
    timeout: 300
  subfinder:
    extra_args: ["-all"]
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)

            nmap_config = config.get_tool_config("nmap")
            assert nmap_config == {"extra_args": ["-T4", "-A"], "timeout": 300}

            subfinder_config = config.get_tool_config("subfinder")
            assert subfinder_config == {"extra_args": ["-all"]}

            # Non-existent tool returns empty dict
            unknown_config = config.get_tool_config("unknown_tool")
            assert unknown_config == {}
        finally:
            os.unlink(config_file)

    def test_get_auth_profile(self):
        """Test getting authentication profiles"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
auth_profiles:
  admin_user:
    username: "admin"
    password: "password123"
    session_cookie: "PHPSESSID"
  api_user:
    api_key: "abc123"
    auth_type: "bearer"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)

            admin_profile = config.get_auth_profile("admin_user")
            assert admin_profile == {
                "username": "admin",
                "password": "password123",
                "session_cookie": "PHPSESSID"
            }

            api_profile = config.get_auth_profile("api_user")
            assert api_profile == {
                "api_key": "abc123",
                "auth_type": "bearer"
            }

            # Non-existent profile returns None
            unknown_profile = config.get_auth_profile("unknown_user")
            assert unknown_profile is None
        finally:
            os.unlink(config_file)

    def test_create_scope_checker(self):
        """Test creating a ScopeChecker from config"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
out_of_scope_urls:
  - "admin.example.com"
out_of_scope_ips:
  - "192.168.1.100"
out_of_scope_attack_vectors:
  - "sqli"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)
            checker = config.create_scope_checker()

            # Test that checker is properly configured
            assert checker.is_in_scope("example.com") is True
            assert checker.is_in_scope("admin.example.com") is False
            assert checker.is_in_scope("192.168.1.100") is False
            assert checker.is_attack_vector_allowed("sqli") is False
            assert checker.is_attack_vector_allowed("xss") is True
        finally:
            os.unlink(config_file)

    def test_save_config(self):
        """Test saving configuration to YAML"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
rate_limit: 10
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            output_file = f.name

        try:
            config = ConfigLoader(config_file)
            config.save(output_file)

            # Load saved config
            saved_config = ConfigLoader(output_file)
            assert saved_config.company_name == "TestCorp"
            assert saved_config.base_domain == "example.com"
            assert saved_config.rate_limit == 10
        finally:
            os.unlink(config_file)
            if os.path.exists(output_file):
                os.unlink(output_file)

    def test_default_values(self):
        """Test default values for optional fields"""
        config_content = """
company_name: "TestCorp"
base_domain: "example.com"
"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
            f.write(config_content)
            config_file = f.name

        try:
            config = ConfigLoader(config_file)

            # Check defaults
            assert config.rate_limit is None or isinstance(config.rate_limit, (int, float))
            assert config.custom_headers is None or isinstance(config.custom_headers, dict)
            assert config.wildcard_urls is None or isinstance(config.wildcard_urls, list)
            assert config.in_scope_urls is None or isinstance(config.in_scope_urls, list)
            assert config.out_of_scope_urls is None or isinstance(config.out_of_scope_urls, list)
            assert config.notes is None or isinstance(config.notes, str)
        finally:
            os.unlink(config_file)
