# wstg_orchestrator/utils/parser_utils.py
import re
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def extract_params_from_url(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


def extract_urls_from_text(text: str) -> list[str]:
    patterns = [
        r'["\'](/[a-zA-Z0-9_/\-\.]+(?:\?[^"\']*)?)["\']',
        r'["\']((https?://)[a-zA-Z0-9_/\-\.]+(?:\?[^"\']*)?)["\']',
    ]
    urls = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            urls.append(match.group(1))
    return list(set(urls))


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    deduped = {k: v[0] for k, v in params.items()}
    normalized_query = urlencode(deduped) if deduped else ""
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        normalized_query,
        "",
    ))


def deduplicate_urls(urls: list[str]) -> list[str]:
    seen = set()
    result = []
    for url in urls:
        norm = normalize_url(url)
        if norm not in seen:
            seen.add(norm)
            result.append(url)
    return result


def diff_responses(body_a: str, body_b: str) -> dict:
    ratio = SequenceMatcher(None, body_a, body_b).ratio()
    return {
        "identical": body_a == body_b,
        "similarity": ratio,
        "length_diff": len(body_b) - len(body_a),
    }


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def extract_forms_from_html(html: str) -> list[dict]:
    parser = _FormParser()
    parser.feed(html)
    return parser.forms


_UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
_NUMERIC_ID_RE = re.compile(r'/(\d{1,10})(?:/|$|\?)')


def detect_id_patterns(urls: list[str]) -> list[dict]:
    results = []
    for url in urls:
        for match in _UUID_RE.finditer(url):
            results.append({"url": url, "type": "uuid", "value": match.group()})
        for match in _NUMERIC_ID_RE.finditer(url):
            results.append({"url": url, "type": "numeric", "value": match.group(1)})
    return results