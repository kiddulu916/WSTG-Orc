import pytest

from wstg_orchestrator.utils.scope_checker import ScopeChecker, OutOfScopeError


class TestScopeChecker:
    def test_in_scope_subdomain(self):
        """Test that subdomains of base domain are in scope"""
        checker = ScopeChecker(base_domain="example.com")

        assert checker.is_in_scope("example.com") is True
        assert checker.is_in_scope("sub.example.com") is True
        assert checker.is_in_scope("api.sub.example.com") is True
        assert checker.is_in_scope("https://example.com/path") is True

    def test_out_of_scope_different_domain(self):
        """Test that URLs without base domain are out of scope"""
        checker = ScopeChecker(base_domain="example.com")

        assert checker.is_in_scope("otherdomain.com") is False
        assert checker.is_in_scope("example.org") is False
        assert checker.is_in_scope("notexample.com") is False

    def test_blacklisted_url(self):
        """Test that blacklisted URLs are out of scope"""
        checker = ScopeChecker(
            base_domain="example.com",
            out_of_scope_urls=["admin.example.com", "dev.example.com"]
        )

        assert checker.is_in_scope("example.com") is True
        assert checker.is_in_scope("api.example.com") is True
        assert checker.is_in_scope("admin.example.com") is False
        assert checker.is_in_scope("dev.example.com") is False

    def test_wildcard_blacklist(self):
        """Test wildcard patterns in blacklist"""
        checker = ScopeChecker(
            base_domain="example.com",
            out_of_scope_urls=["*.internal.example.com", "test-*.example.com"]
        )

        assert checker.is_in_scope("example.com") is True
        assert checker.is_in_scope("api.example.com") is True
        assert checker.is_in_scope("dev.internal.example.com") is False
        assert checker.is_in_scope("prod.internal.example.com") is False
        assert checker.is_in_scope("test-server.example.com") is False
        assert checker.is_in_scope("test-api.example.com") is False

    def test_blacklisted_ips(self):
        """Test that blacklisted IPs are out of scope"""
        checker = ScopeChecker(
            base_domain="example.com",
            out_of_scope_ips=["192.168.1.1", "10.0.0.0/8"]
        )

        assert checker.is_in_scope("example.com") is True
        assert checker.is_in_scope("192.168.1.1") is False
        assert checker.is_in_scope("10.0.0.1") is False

    def test_attack_vector_allowed(self):
        """Test attack vector filtering"""
        checker = ScopeChecker(
            base_domain="example.com",
            out_of_scope_attack_vectors=["sqli", "xss"]
        )

        assert checker.is_attack_vector_allowed("csrf") is True
        assert checker.is_attack_vector_allowed("idor") is True
        assert checker.is_attack_vector_allowed("sqli") is False
        assert checker.is_attack_vector_allowed("xss") is False

    def test_attack_vector_allowed_no_restrictions(self):
        """Test that all attack vectors are allowed by default"""
        checker = ScopeChecker(base_domain="example.com")

        assert checker.is_attack_vector_allowed("sqli") is True
        assert checker.is_attack_vector_allowed("xss") is True
        assert checker.is_attack_vector_allowed("csrf") is True

    def test_out_of_scope_error_exception(self):
        """Test OutOfScopeError exception exists"""
        error = OutOfScopeError("test message")
        assert isinstance(error, Exception)
        assert str(error) == "test message"
