# tests/test_rate_limiter.py
import time
import pytest
from wstg_orchestrator.utils.rate_limit_handler import RateLimiter


def test_rate_limiter_allows_within_limit():
    rl = RateLimiter(requests_per_second=100, base_domain="example.com")
    start = time.monotonic()
    for _ in range(5):
        rl.acquire("https://app.example.com/test")
    elapsed = time.monotonic() - start
    assert elapsed < 1.0


def test_rate_limiter_skips_passive(monkeypatch):
    rl = RateLimiter(requests_per_second=1, base_domain="example.com")
    start = time.monotonic()
    for _ in range(50):
        rl.acquire("https://web.archive.org/something")
    elapsed = time.monotonic() - start
    assert elapsed < 0.5


def test_rate_limiter_skips_non_target():
    rl = RateLimiter(requests_per_second=1, base_domain="example.com")
    start = time.monotonic()
    for _ in range(50):
        rl.acquire("https://cve.circl.lu/api/search")
    elapsed = time.monotonic() - start
    assert elapsed < 0.5


def test_backoff_on_429():
    rl = RateLimiter(requests_per_second=100, base_domain="example.com")
    original = rl._current_rps
    rl.report_block("https://app.example.com")
    assert rl._current_rps < original


def test_recovery_after_backoff():
    rl = RateLimiter(requests_per_second=100, base_domain="example.com")
    rl.report_block("https://app.example.com")
    backed_off = rl._current_rps
    rl.report_success("https://app.example.com")
    assert rl._current_rps >= backed_off