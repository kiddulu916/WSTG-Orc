# wstg_orchestrator/utils/http_utils.py
import logging
from dataclasses import dataclass, field
import requests

from wstg_orchestrator.utils.scope_checker import ScopeChecker, OutOfScopeError
from wstg_orchestrator.utils.rate_limit_handler import RateLimiter

logger = logging.getLogger(__name__)


@dataclass
class HttpResponse:
    status_code: int
    headers: dict
    text: str
    content: bytes
    url: str
    elapsed: float
    request_method: str = ""
    request_url: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str | None = None


class HttpClient:
    def __init__(
        self,
        scope_checker: ScopeChecker,
        rate_limiter: RateLimiter,
        custom_headers: dict | None = None,
        timeout: int = 30,
        proxy: str | None = None,
        retries: int = 2,
    ):
        self._scope_checker = scope_checker
        self._rate_limiter = rate_limiter
        self._custom_headers = custom_headers or {}
        self._timeout = timeout
        self._retries = retries
        self._session = requests.Session()
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
            self._session.verify = False

    def _build_headers(self, extra_headers: dict | None = None) -> dict:
        headers = dict(self._custom_headers)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        data: str | dict | None = None,
        json_data: dict | None = None,
        params: dict | None = None,
        timeout: int | None = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        if not self._scope_checker.is_in_scope(url):
            raise OutOfScopeError(f"URL out of scope: {url}")

        self._rate_limiter.acquire(url)
        merged_headers = self._build_headers(headers)

        resp = self._session.request(
            method=method,
            url=url,
            headers=merged_headers,
            data=data,
            json=json_data,
            params=params,
            timeout=timeout or self._timeout,
            allow_redirects=allow_redirects,
        )

        if resp.status_code == 429:
            self._rate_limiter.report_block(url)
        else:
            self._rate_limiter.report_success(url)

        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            content=resp.content,
            url=resp.url,
            elapsed=resp.elapsed.total_seconds(),
            request_method=method,
            request_url=url,
            request_headers=merged_headers,
            request_body=str(data) if data else None,
        )

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> HttpResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> HttpResponse:
        return self.request("DELETE", url, **kwargs)

    def options(self, url: str, **kwargs) -> HttpResponse:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)

    def try_request(
        self,
        url: str,
        method: str = "GET",
        **kwargs,
    ) -> HttpResponse:
        """Make a request to a scheme-stripped URL.

        Tries https:// first, falls back to http:// on connection failure.
        """
        if "://" in url:
            return self.request(method, url, **kwargs)

        try:
            return self.request(method, f"https://{url}", **kwargs)
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            pass

        return self.request(method, f"http://{url}", **kwargs)