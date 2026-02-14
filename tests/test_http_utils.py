# tests/test_http_utils.py
import pytest
from unittest.mock import patch, MagicMock
from wstg_orchestrator.utils.http_utils import HttpClient
from wstg_orchestrator.utils.scope_checker import ScopeChecker, OutOfScopeError
from wstg_orchestrator.utils.rate_limit_handler import RateLimiter


@pytest.fixture
def client():
    scope = ScopeChecker(base_domain="example.com")
    limiter = RateLimiter(requests_per_second=100, base_domain="example.com")
    return HttpClient(
        scope_checker=scope,
        rate_limiter=limiter,
        custom_headers={"X-Test": "value"},
    )


def test_out_of_scope_raises(client):
    with pytest.raises(OutOfScopeError):
        client.get("https://evil.com/test")


@patch("wstg_orchestrator.utils.http_utils.requests.Session.request")
def test_custom_headers_injected(mock_req, client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.text = "OK"
    mock_resp.content = b"OK"
    mock_resp.url = "https://app.example.com"
    mock_req.return_value = mock_resp
    client.get("https://app.example.com/test")
    call_kwargs = mock_req.call_args
    assert call_kwargs[1]["headers"]["X-Test"] == "value"


@patch("wstg_orchestrator.utils.http_utils.requests.Session.request")
def test_returns_structured_response(mock_req, client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "nginx"}
    mock_resp.text = "OK"
    mock_resp.content = b"OK"
    mock_resp.url = "https://app.example.com/test"
    mock_resp.elapsed.total_seconds.return_value = 0.5
    mock_req.return_value = mock_resp
    result = client.get("https://app.example.com/test")
    assert result.status_code == 200
    assert result.headers["Server"] == "nginx"


@patch("wstg_orchestrator.utils.http_utils.requests.Session.request")
def test_429_triggers_backoff(mock_req, client):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.headers = {}
    mock_resp.text = "Too Many Requests"
    mock_resp.content = b"Too Many Requests"
    mock_resp.url = "https://app.example.com/test"
    mock_resp.elapsed.total_seconds.return_value = 0.1
    mock_req.return_value = mock_resp
    original_rps = client._rate_limiter._current_rps
    client.get("https://app.example.com/test")
    assert client._rate_limiter._current_rps < original_rps