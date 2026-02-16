# tests/test_scope_checker.py
import pytest
from wstg_orchestrator.utils.scope_checker import ScopeChecker


@pytest.fixture
def checker():
    return ScopeChecker(
        base_domain="example.com",
        out_of_scope_urls=["admin.example.com", "*.internal.example.com"],
        out_of_scope_ips=["10.0.0.1"],
        out_of_scope_attack_vectors=["dos", "social_engineering"],
    )


def test_in_scope_subdomain(checker):
    assert checker.is_in_scope("https://app.example.com/api") is True


def test_out_of_scope_blacklisted_url(checker):
    assert checker.is_in_scope("https://admin.example.com") is False


def test_out_of_scope_wildcard(checker):
    assert checker.is_in_scope("https://secret.internal.example.com") is False


def test_out_of_scope_no_base_domain(checker):
    assert checker.is_in_scope("https://evil.com") is False


def test_out_of_scope_ip(checker):
    assert checker.is_in_scope("http://10.0.0.1:8080/test") is False


def test_in_scope_related_company(checker):
    assert checker.is_in_scope("https://partner.example.com/login") is True


def test_attack_vector_allowed(checker):
    assert checker.is_attack_vector_allowed("sqli") is True


def test_attack_vector_blocked(checker):
    assert checker.is_attack_vector_allowed("dos") is False


# --- New tests for expanded scope and out-of-scope pattern types ---


@pytest.fixture
def expanded_checker():
    return ScopeChecker(
        base_domain="example.com",
        wildcard_urls=["example.com", "api.example.com"],
        in_scope_urls=["partner.com", "app.partner.com/dashboard"],
        out_of_scope_urls=["admin.example.com", "*.internal.example.com"],
        out_of_scope_ips=["10.0.0.1"],
        out_of_scope_attack_vectors=["dos"],
    )


def test_in_scope_via_wildcard_urls(expanded_checker):
    assert expanded_checker.is_in_scope("sub.api.example.com") is True


def test_in_scope_via_in_scope_urls_hostname(expanded_checker):
    assert expanded_checker.is_in_scope("partner.com") is True


def test_in_scope_via_in_scope_urls_subdomain(expanded_checker):
    assert expanded_checker.is_in_scope("app.partner.com") is True


def test_out_of_scope_still_wins(expanded_checker):
    assert expanded_checker.is_in_scope("admin.example.com") is False


def test_unknown_domain_still_rejected(expanded_checker):
    assert expanded_checker.is_in_scope("evil.com") is False


@pytest.fixture
def pattern_checker():
    return ScopeChecker(
        base_domain="example.com",
        wildcard_urls=["example.com"],
        out_of_scope_urls=[
            "*.internal.example.com",
            "example.com/admin",
            "*/self-service/*",
        ],
    )


def test_oos_domain_wildcard_blocks_subdomain(pattern_checker):
    assert pattern_checker.is_in_scope("secret.internal.example.com") is False


def test_oos_domain_wildcard_allows_other(pattern_checker):
    assert pattern_checker.is_in_scope("app.example.com") is True


def test_oos_domain_path_prefix_blocks(pattern_checker):
    assert pattern_checker.is_in_scope("example.com/admin") is False
    assert pattern_checker.is_in_scope("example.com/admin/users") is False


def test_oos_domain_path_prefix_allows_other(pattern_checker):
    assert pattern_checker.is_in_scope("example.com/api") is True


def test_oos_path_component_blocks_any_domain(pattern_checker):
    assert pattern_checker.is_in_scope("example.com/v1/self-service/portal") is False
    assert pattern_checker.is_in_scope("app.example.com/self-service/test") is False


def test_oos_path_component_allows_non_matching(pattern_checker):
    assert pattern_checker.is_in_scope("example.com/api/users") is True


def test_add_in_scope_hostnames_makes_domain_pass(expanded_checker):
    """Dynamically added hostnames pass is_in_scope()."""
    assert expanded_checker.is_in_scope("newdomain.com") is False
    expanded_checker.add_in_scope_hostnames(["newdomain.com"])
    assert expanded_checker.is_in_scope("newdomain.com") is True


def test_add_in_scope_hostnames_case_insensitive(expanded_checker):
    """Added hostnames are lowercased for consistent matching."""
    expanded_checker.add_in_scope_hostnames(["NewDomain.COM"])
    assert expanded_checker.is_in_scope("newdomain.com") is True


def test_add_in_scope_hostnames_no_duplicates(expanded_checker):
    """Adding an already in-scope hostname doesn't break anything."""
    expanded_checker.add_in_scope_hostnames(["partner.com"])
    assert expanded_checker.is_in_scope("partner.com") is True