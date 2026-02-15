# tests/test_parser_utils.py
import pytest
from wstg_orchestrator.utils.parser_utils import (
    extract_params_from_url,
    extract_urls_from_text,
    normalize_url,
    deduplicate_urls,
    diff_responses,
    extract_forms_from_html,
    detect_id_patterns,
    strip_scheme,
    strip_wildcard_prefix,
)


def test_extract_params_from_url():
    params = extract_params_from_url("https://example.com/search?q=test&page=1&id=42")
    assert {"q", "page", "id"} == set(params.keys())


def test_extract_urls_from_text():
    text = 'var url = "/api/users"; fetch("/api/orders/123");'
    urls = extract_urls_from_text(text)
    assert "/api/users" in urls
    assert "/api/orders/123" in urls


def test_normalize_url():
    assert normalize_url("https://Example.COM/Path/?a=1&a=1") == "https://example.com/Path/?a=1"


def test_deduplicate_urls():
    urls = [
        "https://example.com/a",
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert len(deduplicate_urls(urls)) == 2


def test_diff_responses_identical():
    result = diff_responses("same body", "same body")
    assert result["identical"] is True


def test_diff_responses_different():
    result = diff_responses("body one data", "body two data")
    assert result["identical"] is False
    assert result["similarity"] < 1.0


def test_extract_forms_from_html():
    html = '<form action="/login" method="POST"><input name="user"><input name="pass" type="password"><button type="submit">Go</button></form>'
    forms = extract_forms_from_html(html)
    assert len(forms) == 1
    assert forms[0]["action"] == "/login"
    assert forms[0]["method"] == "POST"
    assert "user" in [f["name"] for f in forms[0]["inputs"]]


def test_detect_id_patterns():
    urls = [
        "https://example.com/user/123",
        "https://example.com/item/550e8400-e29b-41d4-a716-446655440000",
        "https://example.com/about",
    ]
    result = detect_id_patterns(urls)
    assert any(r["type"] == "numeric" for r in result)
    assert any(r["type"] == "uuid" for r in result)


def test_strip_scheme_https():
    assert strip_scheme("https://example.com") == "example.com"


def test_strip_scheme_http():
    assert strip_scheme("http://example.com/path") == "example.com/path"


def test_strip_scheme_no_scheme():
    assert strip_scheme("example.com") == "example.com"


def test_strip_scheme_preserves_path_and_query():
    assert strip_scheme("https://example.com/api/v1?key=val") == "example.com/api/v1?key=val"


def test_strip_scheme_preserves_port():
    assert strip_scheme("http://example.com:8080/path") == "example.com:8080/path"


def test_strip_scheme_preserves_subdomain():
    assert strip_scheme("https://sub.example.com/path") == "sub.example.com/path"


def test_strip_scheme_empty_string():
    assert strip_scheme("") == ""


def test_strip_wildcard_prefix_standard():
    assert strip_wildcard_prefix("*.example.com") == "example.com"


def test_strip_wildcard_prefix_no_wildcard():
    assert strip_wildcard_prefix("example.com") == "example.com"


def test_strip_wildcard_prefix_nested():
    assert strip_wildcard_prefix("*.api.example.com") == "api.example.com"


def test_strip_wildcard_prefix_with_scheme():
    assert strip_wildcard_prefix("https://*.example.com") == "example.com"