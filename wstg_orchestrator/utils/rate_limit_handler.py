# wstg_orchestrator/utils/rate_limit_handler.py
import threading
import time
import logging

logger = logging.getLogger(__name__)

PASSIVE_DOMAINS = [
    "web.archive.org", "crt.sh", "dns", "whois",
    "google.com", "bing.com", "github.com",
    "cve.circl.lu", "services.nvd.nist.gov",
]


class RateLimiter:
    def __init__(self, requests_per_second: int, base_domain: str):
        self._max_rps = requests_per_second
        self._current_rps = float(requests_per_second)
        self._base_domain = base_domain.lower()
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._min_interval = 1.0 / self._current_rps if self._current_rps > 0 else 0

    def _is_target_url(self, url: str) -> bool:
        url_lower = url.lower()
        if self._base_domain in url_lower:
            return True
        return False

    def _is_passive(self, url: str) -> bool:
        url_lower = url.lower()
        for domain in PASSIVE_DOMAINS:
            if domain in url_lower:
                return True
        return False

    def acquire(self, url: str):
        if self._is_passive(url) or not self._is_target_url(url):
            return

        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            wait = self._min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def report_block(self, url: str):
        with self._lock:
            self._current_rps = max(1.0, self._current_rps / 2)
            self._min_interval = 1.0 / self._current_rps
            logger.warning(
                f"Rate limited on {url}. Backing off to {self._current_rps:.1f} rps"
            )

    def report_success(self, url: str):
        with self._lock:
            if self._current_rps < self._max_rps:
                self._current_rps = min(self._max_rps, self._current_rps * 1.1)
                self._min_interval = 1.0 / self._current_rps