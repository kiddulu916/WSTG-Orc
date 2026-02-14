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