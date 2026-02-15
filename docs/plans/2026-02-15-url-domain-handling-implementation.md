# URL & Domain Handling Redesign - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Standardize all URL storage to be scheme-stripped, separate enumeration_domains from in_scope_urls, expand ScopeChecker to validate against wildcard_urls and in_scope_urls, add three-pattern out-of-scope matching, filter out-of-scope on state ingest, reorder recon pipeline, and add try_request utility.

**Architecture:** URLs are stripped of `http://`/`https://` at every boundary (user input, tool output, state storage). ScopeChecker becomes the single authority for scope validation using base_domain + wildcard_urls + in_scope_urls as positive scope, with three out-of-scope pattern types. StateManager filters out-of-scope entries on `enrich()`. Recon pipeline reorders to: subdomain enumeration -> URL harvesting -> live host validation.

**Tech Stack:** Python 3.11+, pytest, unittest.mock

---

### Task 1: Add `strip_scheme()` utility

**Files:**
- Modify: `wstg_orchestrator/utils/parser_utils.py` (add after line 5)
- Test: `tests/test_parser_utils.py`

**Step 1: Write the failing tests**

Add to `tests/test_parser_utils.py`:

```python
from wstg_orchestrator.utils.parser_utils import strip_scheme

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
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_parser_utils.py -v -k "strip_scheme"`
Expected: FAIL with ImportError

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/parser_utils.py` after the imports (line 5):

```python
import re

def strip_scheme(url: str) -> str:
    """Strip http:// or https:// from a URL, preserving everything else."""
    if not url:
        return url
    return re.sub(r'^https?://', '', url)
```

Note: `re` is already imported in parser_utils.py, so just add the function.

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_parser_utils.py -v -k "strip_scheme"`
Expected: All 7 PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/parser_utils.py tests/test_parser_utils.py
git commit -m "feat: add strip_scheme() utility to parser_utils"
```

---

### Task 2: Add `strip_wildcard_prefix()` utility

**Files:**
- Modify: `wstg_orchestrator/utils/parser_utils.py`
- Test: `tests/test_parser_utils.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.parser_utils import strip_wildcard_prefix

def test_strip_wildcard_prefix_standard():
    assert strip_wildcard_prefix("*.example.com") == "example.com"

def test_strip_wildcard_prefix_no_wildcard():
    assert strip_wildcard_prefix("example.com") == "example.com"

def test_strip_wildcard_prefix_nested():
    assert strip_wildcard_prefix("*.api.example.com") == "api.example.com"

def test_strip_wildcard_prefix_with_scheme():
    assert strip_wildcard_prefix("https://*.example.com") == "example.com"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_parser_utils.py -v -k "strip_wildcard"`
Expected: FAIL with ImportError

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/parser_utils.py`:

```python
def strip_wildcard_prefix(url: str) -> str:
    """Strip http(s):// scheme and *. wildcard prefix from a URL."""
    result = strip_scheme(url)
    if result.startswith("*."):
        result = result[2:]
    return result
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_parser_utils.py -v -k "strip_wildcard"`
Expected: All 4 PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/parser_utils.py tests/test_parser_utils.py
git commit -m "feat: add strip_wildcard_prefix() utility"
```

---

### Task 3: Add `parse_url_components()` utility

**Files:**
- Modify: `wstg_orchestrator/utils/parser_utils.py`
- Test: `tests/test_parser_utils.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.parser_utils import parse_url_components

def test_parse_url_components_full():
    result = parse_url_components("https://api.example.com/v1/users?id=123")
    assert result["hostname"] == "api.example.com"
    assert result["path"] == "api.example.com/v1/users"
    assert result["full"] == "api.example.com/v1/users?id=123"
    assert result["has_query"] is True

def test_parse_url_components_no_query():
    result = parse_url_components("https://example.com/docs")
    assert result["hostname"] == "example.com"
    assert result["path"] == "example.com/docs"
    assert result["full"] == "example.com/docs"
    assert result["has_query"] is False

def test_parse_url_components_bare_hostname():
    result = parse_url_components("example.com")
    assert result["hostname"] == "example.com"
    assert result["path"] == "example.com"
    assert result["full"] == "example.com"
    assert result["has_query"] is False

def test_parse_url_components_no_scheme():
    result = parse_url_components("api.example.com/v1/users?id=123&name=test")
    assert result["hostname"] == "api.example.com"
    assert result["path"] == "api.example.com/v1/users"
    assert result["full"] == "api.example.com/v1/users?id=123&name=test"
    assert result["has_query"] is True

def test_parse_url_components_root_path():
    result = parse_url_components("https://example.com/")
    assert result["hostname"] == "example.com"
    assert result["path"] == "example.com"
    assert result["has_query"] is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_parser_utils.py -v -k "parse_url_components"`
Expected: FAIL with ImportError

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/parser_utils.py`:

```python
def parse_url_components(url: str) -> dict:
    """Parse a URL into hostname, path (no query), and full (with query).

    All results are scheme-stripped. Returns:
        hostname: bare hostname (e.g., "api.example.com")
        path: hostname + path without query (e.g., "api.example.com/v1/users")
        full: hostname + path + query (e.g., "api.example.com/v1/users?id=123")
        has_query: True if URL has query string parameters
    """
    stripped = strip_scheme(url)
    if not stripped:
        return {"hostname": "", "path": "", "full": "", "has_query": False}

    # Use urlparse with a scheme to get reliable parsing
    to_parse = url if "://" in url else f"https://{url}"
    parsed = urlparse(to_parse)

    hostname = parsed.hostname or ""
    path_part = parsed.path.rstrip("/")
    query = parsed.query

    # Build path: hostname + path (no trailing slash, no query)
    if path_part and path_part != "/":
        path = f"{hostname}{path_part}"
    else:
        path = hostname

    # Build full: hostname + path + query
    if query:
        full = f"{path}?{query}"
    else:
        full = path

    return {
        "hostname": hostname,
        "path": path,
        "full": full,
        "has_query": bool(query),
    }
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_parser_utils.py -v -k "parse_url_components"`
Expected: All 5 PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/parser_utils.py tests/test_parser_utils.py
git commit -m "feat: add parse_url_components() URL parsing utility"
```

---

### Task 4: Update ScopeBuilder to strip schemes and wildcard prefixes

**Files:**
- Modify: `wstg_orchestrator/scope_builder.py`
- Test: `tests/test_scope_builder.py`

**Step 1: Write the failing tests**

Replace existing tests and add new ones in `tests/test_scope_builder.py`:

```python
def test_build_strips_scheme_from_base_domain():
    inputs = iter([
        "TestCorp",                          # company name
        "https://testcorp.com",              # base domain WITH scheme
        "",                                  # wildcard urls (empty -> default)
        "",                                  # in-scope urls
        "",                                  # in-scope ips
        "",                                  # out-of-scope urls
        "",                                  # out-of-scope ips
        "",                                  # out-of-scope attack vectors
        "",                                  # rate limit (default)
        "",                                  # custom headers
        "",                                  # auth profiles (skip)
        "",                                  # callback host (default)
        "",                                  # callback port (default)
        "",                                  # notes
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        builder = ScopeBuilder()
        config = builder.build()
    assert config["program_scope"]["base_domain"] == "testcorp.com"


def test_build_strips_scheme_and_wildcard_from_wildcard_urls():
    inputs = iter([
        "TestCorp",
        "testcorp.com",
        "https://*.testcorp.com, http://*.api.testcorp.com",
        "", "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["wildcard_urls"] == ["testcorp.com", "api.testcorp.com"]


def test_build_wildcard_default_stripped():
    """When no wildcard URLs provided, default is base_domain (no *. prefix)."""
    inputs = iter([
        "TestCorp", "testcorp.com",
        "",  # wildcard urls (empty -> default)
        "", "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["wildcard_urls"] == ["testcorp.com"]


def test_build_strips_scheme_from_in_scope_urls():
    inputs = iter([
        "TestCorp", "testcorp.com", "",
        "https://app.testcorp.com/dashboard, http://partner.com",
        "", "", "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["in_scope_urls"] == [
        "app.testcorp.com/dashboard", "partner.com"
    ]


def test_build_strips_scheme_from_out_of_scope_urls():
    inputs = iter([
        "TestCorp", "testcorp.com", "", "",  "",
        "https://admin.testcorp.com/panel, *.internal.testcorp.com",
        "", "", "", "", "", "", "", "",
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        config = ScopeBuilder().build()
    assert config["program_scope"]["out_of_scope_urls"] == [
        "admin.testcorp.com/panel", "*.internal.testcorp.com"
    ]
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scope_builder.py -v -k "strips_scheme or wildcard_default_stripped"`
Expected: FAIL (values still have schemes/wildcards)

**Step 3: Write minimal implementation**

Modify `wstg_orchestrator/scope_builder.py`:

Add import at top:
```python
from wstg_orchestrator.utils.parser_utils import strip_scheme, strip_wildcard_prefix
```

In the `build()` method, change `base_domain` line (line 11):
```python
base_domain = strip_scheme(cli_input("Base domain (e.g., example.com): ").strip())
```

Change `wildcard_urls` handling (lines 13-17):
```python
wildcard_urls = [
    strip_wildcard_prefix(item)
    for item in self._parse_list(
        cli_input("Wildcard URLs (e.g., *.example.com, *.sub.example.com; comma-separated, or empty): ")
    )
]
if not wildcard_urls:
    wildcard_urls = [base_domain]
```

Change `in_scope_urls` (lines 19-21):
```python
in_scope_urls = [
    strip_scheme(item)
    for item in self._parse_list(
        cli_input("In-scope URLs (comma-separated, or empty): ")
    )
]
```

Change `out_of_scope_urls` (lines 25-27):
```python
out_of_scope_urls = [
    strip_scheme(item)
    for item in self._parse_list(
        cli_input("Out-of-scope URLs (comma-separated, or empty): ")
    )
]
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scope_builder.py -v`
Expected: All PASS (update existing test assertions that expected `*.` prefix)

**Step 5: Update existing test assertions**

In `test_build_config_from_inputs`, update the wildcard assertion:
```python
# Old: assert config["program_scope"]["wildcard_urls"] == ["*.testcorp.com", "*.api.testcorp.com"]
assert config["program_scope"]["wildcard_urls"] == ["testcorp.com", "api.testcorp.com"]
```

In `test_build_config_wildcard_default_fallback`, update:
```python
# Old: assert config["program_scope"]["wildcard_urls"] == ["*.testcorp.com"]
assert config["program_scope"]["wildcard_urls"] == ["testcorp.com"]
```

**Step 6: Run all scope_builder tests to verify**

Run: `pytest tests/test_scope_builder.py -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add wstg_orchestrator/scope_builder.py tests/test_scope_builder.py
git commit -m "feat: strip schemes and wildcard prefixes in ScopeBuilder input"
```

---

### Task 5: Update ConfigLoader - enumeration_domains excludes in_scope_urls

**Files:**
- Modify: `wstg_orchestrator/utils/config_loader.py:37-69`
- Test: `tests/test_config_loader.py`

**Step 1: Write the failing tests**

Update/add tests in `tests/test_config_loader.py`. Config fixtures now have stripped wildcards:

```python
def test_enumeration_domains_excludes_in_scope_urls():
    """enumeration_domains should only combine base_domain + wildcard_urls, NOT in_scope_urls."""
    cfg = {
        "program_scope": {
            "base_domain": "testcorp.com",
            "wildcard_urls": ["testcorp.com", "api.testcorp.com"],
            "in_scope_urls": ["partner.com", "app.testcorp.com/dashboard"],
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        domains = config.enumeration_domains
        assert "testcorp.com" in domains
        assert "api.testcorp.com" in domains
        assert "partner.com" not in domains
        assert "app.testcorp.com" not in domains
    finally:
        os.remove(path)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_config_loader.py::test_enumeration_domains_excludes_in_scope_urls -v`
Expected: FAIL (partner.com and app.testcorp.com will be in the list)

**Step 3: Write minimal implementation**

Replace `enumeration_domains` property in `wstg_orchestrator/utils/config_loader.py` (lines 47-69):

```python
@property
def enumeration_domains(self) -> list[str]:
    """
    Return all domains that should be enumerated for subdomains.
    Combines base_domain and wildcard_urls only. in_scope_urls are excluded.
    Deduplicated, order preserved.
    """
    domains = []
    if self.base_domain:
        domains.append(self.base_domain)
    domains.extend(self.wildcard_urls)
    return list(dict.fromkeys(domains))
```

Also remove the `wildcard_domains` property (lines 37-44) since wildcard_urls are now stored without `*.` prefix, making `wildcard_domains` redundant. And remove the `urlparse` import from config_loader.py (line 3) if no longer needed.

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_config_loader.py::test_enumeration_domains_excludes_in_scope_urls -v`
Expected: PASS

**Step 5: Update existing tests**

Update `sample_config` fixture to use stripped wildcards:
```python
"wildcard_urls": ["testcorp.com"],  # was ["*.testcorp.com"]
```

Update `test_wildcard_domains` tests — either remove them (property is gone) or rename to test `enumeration_domains`.

Update `test_enumeration_domains` to not expect in_scope_url hostnames:
```python
def test_enumeration_domains(config_file):
    config = ConfigLoader(config_file)
    domains = config.enumeration_domains
    assert domains[0] == "testcorp.com"
    # in_scope_urls should NOT be in enumeration_domains
    assert "app.testcorp.com" not in domains
    assert "api.testcorp.com" not in domains
```

Remove `test_enumeration_domains_with_full_urls` — no longer relevant since in_scope_urls are excluded.

Update `test_enumeration_domains_deduplicates` to only use base_domain + wildcard_urls.

**Step 6: Run all config_loader tests**

Run: `pytest tests/test_config_loader.py -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add wstg_orchestrator/utils/config_loader.py tests/test_config_loader.py
git commit -m "feat: enumeration_domains excludes in_scope_urls, remove wildcard_domains"
```

---

### Task 6: Update ScopeChecker - positive scope with wildcard_urls and in_scope_urls

**Files:**
- Modify: `wstg_orchestrator/utils/scope_checker.py`
- Test: `tests/test_scope_checker.py`

**Step 1: Write the failing tests**

Add to `tests/test_scope_checker.py`:

```python
@pytest.fixture
def expanded_checker():
    """Checker with wildcard_urls and in_scope_urls for positive scope."""
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
    """Hostnames from in_scope_urls: exact hostname match, not subdomain expansion."""
    assert expanded_checker.is_in_scope("app.partner.com") is True

def test_out_of_scope_still_wins(expanded_checker):
    assert expanded_checker.is_in_scope("admin.example.com") is False

def test_unknown_domain_still_rejected(expanded_checker):
    assert expanded_checker.is_in_scope("evil.com") is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scope_checker.py -v -k "expanded"`
Expected: FAIL (constructor doesn't accept wildcard_urls/in_scope_urls)

**Step 3: Write minimal implementation**

Replace `wstg_orchestrator/utils/scope_checker.py`:

```python
import fnmatch
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    pass


class ScopeChecker:
    def __init__(
        self,
        base_domain: str,
        wildcard_urls: list[str] | None = None,
        in_scope_urls: list[str] | None = None,
        out_of_scope_urls: list[str] | None = None,
        out_of_scope_ips: list[str] | None = None,
        out_of_scope_attack_vectors: list[str] | None = None,
    ):
        self.base_domain = base_domain.lower()
        self.wildcard_urls = [u.lower() for u in (wildcard_urls or [])]
        self.out_of_scope_urls = [u.lower() for u in (out_of_scope_urls or [])]
        self.out_of_scope_ips = set(out_of_scope_ips or [])
        self.out_of_scope_attack_vectors = set(
            v.lower() for v in (out_of_scope_attack_vectors or [])
        )
        # Extract hostnames from in_scope_urls for positive scope matching
        self._in_scope_hostnames = set()
        for url in (in_scope_urls or []):
            url_lower = url.lower()
            # Extract hostname: strip scheme if present, take first segment before /
            if "://" in url_lower:
                parsed = urlparse(url_lower)
                hostname = parsed.hostname or ""
            else:
                hostname = url_lower.split("/")[0].split(":")[0]
            if hostname:
                self._in_scope_hostnames.add(hostname)

    def is_in_scope(self, target: str) -> bool:
        target_lower = target.lower()
        if "://" not in target_lower:
            target_lower = "https://" + target_lower
        parsed = urlparse(target_lower)
        hostname = parsed.hostname or target_lower
        path = parsed.path or ""

        # Check if IP is blacklisted
        if hostname in self.out_of_scope_ips:
            return False

        # Check out-of-scope patterns (deny takes priority)
        if self._matches_out_of_scope(hostname, path):
            return False

        # Check positive scope: base_domain
        if self.base_domain:
            if hostname == self.base_domain or hostname.endswith("." + self.base_domain):
                return True

        # Check positive scope: wildcard_urls (domain + all subdomains)
        for wc_domain in self.wildcard_urls:
            if hostname == wc_domain or hostname.endswith("." + wc_domain):
                return True

        # Check positive scope: in_scope_urls hostnames (exact match)
        if hostname in self._in_scope_hostnames:
            return True

        return False

    def _matches_out_of_scope(self, hostname: str, path: str) -> bool:
        """Check against three out-of-scope pattern types."""
        for pattern in self.out_of_scope_urls:
            # Type 3: Path component wildcard - */segment/*
            if pattern.startswith("*/") or pattern.startswith("*\\"):
                # Extract the path segment between wildcards
                segment = pattern.strip("*").strip("/")
                if segment and f"/{segment}/" in path:
                    return True
                # Also match if path ends with the segment (no trailing /)
                if segment and path.rstrip("/").endswith(f"/{segment}"):
                    return True
                continue

            # Type 1: Domain wildcard - *.something.com
            if pattern.startswith("*."):
                domain_part = pattern[2:]
                if hostname == domain_part or hostname.endswith("." + domain_part):
                    return True
                continue

            # Type 2: Domain + path prefix - example.com/path
            if "/" in pattern:
                pattern_host = pattern.split("/")[0]
                pattern_path = "/" + "/".join(pattern.split("/")[1:])
                if fnmatch.fnmatch(hostname, pattern_host) and path.startswith(pattern_path):
                    return True
                continue

            # Simple domain match (exact or fnmatch)
            if fnmatch.fnmatch(hostname, pattern):
                return True

        return False

    def is_attack_vector_allowed(self, vector: str) -> bool:
        return vector.lower() not in self.out_of_scope_attack_vectors
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scope_checker.py -v`
Expected: All PASS (existing + new)

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/scope_checker.py tests/test_scope_checker.py
git commit -m "feat: expand ScopeChecker with wildcard_urls, in_scope_urls, three OOS pattern types"
```

---

### Task 7: Add out-of-scope pattern matching tests for all three types

**Files:**
- Test: `tests/test_scope_checker.py`

**Step 1: Write comprehensive pattern matching tests**

```python
@pytest.fixture
def pattern_checker():
    return ScopeChecker(
        base_domain="example.com",
        wildcard_urls=["example.com"],
        out_of_scope_urls=[
            "*.internal.example.com",       # Type 1: domain wildcard
            "example.com/admin",             # Type 2: domain + path prefix
            "*/self-service/*",              # Type 3: path component wildcard
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
```

**Step 2: Run tests**

Run: `pytest tests/test_scope_checker.py -v -k "pattern"`
Expected: All PASS (already implemented in Task 6)

**Step 3: Commit**

```bash
git add tests/test_scope_checker.py
git commit -m "test: add comprehensive out-of-scope pattern matching tests"
```

---

### Task 8: Update ConfigLoader.create_scope_checker() to pass new params

**Files:**
- Modify: `wstg_orchestrator/utils/config_loader.py:109-115`
- Test: `tests/test_config_loader.py`

**Step 1: Write the failing test**

```python
def test_scope_checker_uses_wildcard_and_in_scope():
    cfg = {
        "program_scope": {
            "base_domain": "testcorp.com",
            "wildcard_urls": ["testcorp.com"],
            "in_scope_urls": ["partner.com"],
            "out_of_scope_urls": [],
            "out_of_scope_ips": [],
            "out_of_scope_attack_vectors": [],
        },
    }
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(cfg, f)
    try:
        config = ConfigLoader(path)
        checker = config.create_scope_checker()
        assert checker.is_in_scope("partner.com") is True
        assert checker.is_in_scope("evil.com") is False
    finally:
        os.remove(path)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_config_loader.py::test_scope_checker_uses_wildcard_and_in_scope -v`
Expected: FAIL (partner.com rejected because ScopeChecker doesn't know about it)

**Step 3: Write minimal implementation**

Update `create_scope_checker()` in `wstg_orchestrator/utils/config_loader.py`:

```python
def create_scope_checker(self) -> ScopeChecker:
    return ScopeChecker(
        base_domain=self.base_domain,
        wildcard_urls=self.wildcard_urls,
        in_scope_urls=self.in_scope_urls,
        out_of_scope_urls=self.out_of_scope_urls,
        out_of_scope_ips=self.out_of_scope_ips,
        out_of_scope_attack_vectors=self.out_of_scope_attack_vectors,
    )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_config_loader.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/config_loader.py tests/test_config_loader.py
git commit -m "feat: pass wildcard_urls and in_scope_urls to ScopeChecker from ConfigLoader"
```

---

### Task 9: Update StateManager - add discovered_directory_paths and scope filtering on enrich

**Files:**
- Modify: `wstg_orchestrator/state_manager.py`
- Test: `tests/test_state_manager.py`

**Step 1: Write the failing tests**

```python
from wstg_orchestrator.utils.scope_checker import ScopeChecker

def test_discovered_directory_paths_key_exists(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com")
    assert sm.get("discovered_directory_paths") == []

def test_enrich_filters_out_of_scope(tmp_state_file):
    scope = ScopeChecker(
        base_domain="example.com",
        out_of_scope_urls=["admin.example.com"],
    )
    sm = StateManager(tmp_state_file, target_domain="example.com", scope_checker=scope)
    sm.enrich("discovered_subdomains", ["app.example.com", "admin.example.com", "api.example.com"])
    result = sm.get("discovered_subdomains")
    assert "app.example.com" in result
    assert "api.example.com" in result
    assert "admin.example.com" not in result

def test_enrich_filters_path_component_out_of_scope(tmp_state_file):
    scope = ScopeChecker(
        base_domain="example.com",
        out_of_scope_urls=["*/admin/*"],
    )
    sm = StateManager(tmp_state_file, target_domain="example.com", scope_checker=scope)
    sm.enrich("endpoints", ["example.com/api/users", "example.com/admin/settings"])
    result = sm.get("endpoints")
    assert "example.com/api/users" in result
    assert "example.com/admin/settings" not in result

def test_enrich_without_scope_checker_no_filtering(tmp_state_file):
    """When no scope_checker is provided, enrich works as before."""
    sm = StateManager(tmp_state_file, target_domain="example.com")
    sm.enrich("discovered_subdomains", ["anything.com"])
    assert "anything.com" in sm.get("discovered_subdomains")
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_state_manager.py -v -k "directory_paths or filters"`
Expected: FAIL (scope_checker param not accepted, key doesn't exist)

**Step 3: Write minimal implementation**

Update `wstg_orchestrator/state_manager.py`:

Add `"discovered_directory_paths"` to both `STATE_KEYS` and `LIST_KEYS` lists.

Update `__init__` to accept optional `scope_checker`:
```python
def __init__(self, state_file: str, target_domain: str = "", company_name: str = "", scope_checker=None):
    self._file = state_file
    self._lock = threading.Lock()
    self._scope_checker = scope_checker
    if os.path.exists(state_file) and os.path.getsize(state_file) > 0:
        with open(state_file, "r") as f:
            self._state = json.load(f)
    else:
        self._state = self._fresh_state(target_domain, company_name)
```

Update `enrich()` to filter via scope_checker:
```python
def enrich(self, key: str, values: list):
    with self._lock:
        existing = self._state.get(key, [])
        for v in values:
            if v not in existing:
                if self._scope_checker and not self._is_value_in_scope(v):
                    continue
                existing.append(v)
        self._state[key] = existing

def _is_value_in_scope(self, value) -> bool:
    """Check if a value passes scope filtering.
    Handles both string values and dict values (extracts 'url' key)."""
    if self._scope_checker is None:
        return True
    if isinstance(value, dict):
        target = value.get("url", "")
    else:
        target = str(value)
    if not target:
        return True
    return self._scope_checker.is_in_scope(target)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_state_manager.py -v`
Expected: All PASS (existing tests unaffected since scope_checker defaults to None)

**Step 5: Commit**

```bash
git add wstg_orchestrator/state_manager.py tests/test_state_manager.py
git commit -m "feat: add scope filtering on StateManager.enrich() and discovered_directory_paths key"
```

---

### Task 10: Add `try_request()` to HttpClient

**Files:**
- Modify: `wstg_orchestrator/utils/http_utils.py`
- Test: `tests/test_http_utils.py`

**Step 1: Write the failing tests**

Add to `tests/test_http_utils.py`:

```python
from unittest.mock import patch, MagicMock
from wstg_orchestrator.utils.http_utils import HttpClient, HttpResponse
from wstg_orchestrator.utils.scope_checker import ScopeChecker

@pytest.fixture
def client():
    scope = ScopeChecker(base_domain="example.com")
    limiter = MagicMock()
    limiter.acquire.return_value = None
    limiter.report_success.return_value = None
    return HttpClient(scope_checker=scope, rate_limiter=limiter)

def test_try_request_https_success(client):
    """try_request succeeds with https on first attempt."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.text = "ok"
    mock_resp.content = b"ok"
    mock_resp.url = "https://example.com"
    mock_resp.elapsed.total_seconds.return_value = 0.1
    with patch.object(client._session, 'request', return_value=mock_resp):
        result = client.try_request("example.com")
    assert result.status_code == 200
    assert "https://example.com" in result.request_url

def test_try_request_falls_back_to_http(client):
    """try_request falls back to http when https fails."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    mock_resp.text = "ok"
    mock_resp.content = b"ok"
    mock_resp.url = "http://example.com"
    mock_resp.elapsed.total_seconds.return_value = 0.1

    import requests as req_lib
    def side_effect(method, url, **kwargs):
        if url.startswith("https://"):
            raise req_lib.exceptions.SSLError("SSL failed")
        return mock_resp

    with patch.object(client._session, 'request', side_effect=side_effect):
        result = client.try_request("example.com")
    assert result.status_code == 200
    assert "http://example.com" in result.request_url
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_http_utils.py -v -k "try_request"`
Expected: FAIL (try_request doesn't exist)

**Step 3: Write minimal implementation**

Add to `HttpClient` class in `wstg_orchestrator/utils/http_utils.py`:

```python
def try_request(
    self,
    url: str,
    method: str = "GET",
    **kwargs,
) -> HttpResponse:
    """Make a request to a scheme-stripped URL.

    Tries https:// first, falls back to http:// on connection failure.
    """
    # If URL already has a scheme, use it directly
    if "://" in url:
        return self.request(method, url, **kwargs)

    # Try https first
    try:
        return self.request(method, f"https://{url}", **kwargs)
    except (requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout):
        pass

    # Fall back to http
    return self.request(method, f"http://{url}", **kwargs)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_http_utils.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/http_utils.py tests/test_http_utils.py
git commit -m "feat: add try_request() with https-first, http-fallback to HttpClient"
```

---

### Task 11: Update ReconModule - reorder pipeline and URL harvesting parsing

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_execute_runs_url_harvesting_before_live_hosts(recon_module):
    """URL harvesting must run before live host validation."""
    call_order = []
    async def mock_passive():
        call_order.append("passive_osint")
    async def mock_harvest():
        call_order.append("url_harvesting")
    async def mock_live():
        call_order.append("live_host_validation")
    async def mock_params():
        call_order.append("parameter_harvesting")

    with patch.object(recon_module, '_passive_osint', side_effect=mock_passive):
        with patch.object(recon_module, '_url_harvesting', side_effect=mock_harvest):
            with patch.object(recon_module, '_live_host_validation', side_effect=mock_live):
                with patch.object(recon_module, '_parameter_harvesting', side_effect=mock_params):
                    await recon_module.execute()

    assert call_order.index("url_harvesting") < call_order.index("live_host_validation")


@pytest.mark.asyncio
async def test_url_harvesting_parses_into_three_buckets(recon_module):
    """URL harvesting splits output: hostnames -> subdomains, paths -> endpoints, queries -> parameters."""
    gau_output = [
        "https://api.example.com/v1/users?id=123",
        "https://app.example.com/docs",
        "https://example.com",
    ]
    with patch.object(recon_module, '_run_gau', new_callable=AsyncMock, return_value=gau_output):
        with patch.object(recon_module, '_run_wayback', new_callable=AsyncMock, return_value=[]):
            await recon_module._url_harvesting()

    enrich_calls = {call.args[0]: call.args[1] for call in recon_module.state.enrich.call_args_list}
    # Hostnames go to discovered_subdomains
    assert "api.example.com" in enrich_calls.get("discovered_subdomains", [])
    assert "app.example.com" in enrich_calls.get("discovered_subdomains", [])
    # URL with query -> base path in endpoints, full in parameters
    assert "api.example.com/v1/users" in enrich_calls.get("endpoints", [])
    assert "api.example.com/v1/users?id=123" in enrich_calls.get("parameters", [])


@pytest.mark.asyncio
async def test_live_host_validation_includes_in_scope_urls(recon_module):
    """Live host validation probes discovered_subdomains + in_scope_urls."""
    recon_module.state.get.side_effect = lambda key: {
        "discovered_subdomains": ["app.example.com"],
    }.get(key, [])
    recon_module.config.in_scope_urls = ["partner.com", "extra.example.com"]

    probed_hosts = []
    async def mock_httpx(subdomains):
        probed_hosts.extend(subdomains)
        return [], []

    with patch.object(recon_module, '_run_httpx', side_effect=mock_httpx):
        await recon_module._live_host_validation()

    assert "app.example.com" in probed_hosts
    assert "partner.com" in probed_hosts
    assert "extra.example.com" in probed_hosts
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py -v -k "three_buckets or before_live or includes_in_scope"`
Expected: FAIL

**Step 3: Write minimal implementation**

Update `wstg_orchestrator/modules/reconnaissance.py`:

Add import:
```python
from wstg_orchestrator.utils.parser_utils import (
    extract_params_from_url,
    extract_urls_from_text,
    detect_id_patterns,
    strip_scheme,
    parse_url_components,
)
```

Update `SUBCATEGORIES`:
```python
SUBCATEGORIES = ["passive_osint", "url_harvesting", "live_host_validation", "parameter_harvesting"]
```

Update `execute()`:
```python
async def execute(self):
    if not self.should_skip_subcategory("passive_osint"):
        await self._passive_osint()
        self.mark_subcategory_complete("passive_osint")

    if not self.should_skip_subcategory("url_harvesting"):
        await self._url_harvesting()
        self.mark_subcategory_complete("url_harvesting")

    if not self.should_skip_subcategory("live_host_validation"):
        await self._live_host_validation()
        self.mark_subcategory_complete("live_host_validation")

    if not self.should_skip_subcategory("parameter_harvesting"):
        await self._parameter_harvesting()
        self.mark_subcategory_complete("parameter_harvesting")
```

Update `_passive_osint()` to ONLY do subdomain enumeration (remove gau/wayback/URL handling):
```python
async def _passive_osint(self):
    self.logger.info("Starting passive OSINT - subdomain enumeration")
    all_subdomains = []

    target_domains = self._get_target_domains()
    for domain in target_domains:
        subfinder_results = await self._run_subfinder(domain)
        all_subdomains.extend(subfinder_results)

    all_subdomains = list(set(self._filter_in_scope(all_subdomains)))
    self.state.enrich("discovered_subdomains", all_subdomains)
    self.evidence.log_parsed("reconnaissance", "subdomains", all_subdomains)
    self.logger.info(f"Found {len(all_subdomains)} subdomains")
```

Add new `_url_harvesting()` method:
```python
async def _url_harvesting(self):
    """Harvest URLs from gau/wayback and parse into three buckets."""
    self.logger.info("Starting URL harvesting")

    gau_results = await self._run_gau()
    wayback_results = await self._run_wayback()
    all_urls = gau_results + wayback_results

    new_subdomains = []
    new_endpoints = []
    new_params = []

    for url in all_urls:
        components = parse_url_components(url)
        hostname = components["hostname"]

        if not hostname:
            continue

        # Always extract hostname -> discovered_subdomains
        new_subdomains.append(hostname)

        if components["has_query"]:
            # URL with query string -> parameters (full) + endpoints (base path)
            new_params.append(components["full"])
            new_endpoints.append(components["path"])
        elif components["path"] != hostname:
            # URL with path but no query -> endpoints (classification as
            # endpoint vs directory_path happens later during probing)
            new_endpoints.append(components["path"])

    new_subdomains = list(set(self._filter_in_scope(new_subdomains)))
    new_endpoints = list(set(new_endpoints))
    new_params = list(set(new_params))

    self.state.enrich("discovered_subdomains", new_subdomains)
    self.state.enrich("endpoints", new_endpoints)
    self.state.enrich("parameters", new_params)
    self.evidence.log_parsed("reconnaissance", "harvested_urls", all_urls)
    self.logger.info(
        f"Harvested {len(new_subdomains)} subdomains, "
        f"{len(new_endpoints)} endpoints, {len(new_params)} parameters"
    )
```

Update `_live_host_validation()` to merge in_scope_urls:
```python
async def _live_host_validation(self):
    self.logger.info("Starting live host validation")
    subdomains = self.state.get("discovered_subdomains") or []

    # Merge in_scope_urls (extract hostnames from paths)
    in_scope = getattr(self.config, "in_scope_urls", []) or []
    for url in in_scope:
        hostname = url.split("/")[0].split(":")[0]
        if hostname and hostname not in subdomains:
            subdomains.append(hostname)

    if not subdomains:
        subdomains = [self.config.base_domain]

    live_hosts = []
    technologies = []

    if self._cmd.is_tool_available("httpx"):
        live_hosts, technologies = await self._run_httpx(subdomains)
    else:
        self.logger.warning("httpx not found, using fallback HTTP probing")
        live_hosts, technologies = await self._fallback_probe(subdomains)

    self.state.enrich("live_hosts", live_hosts)
    self.state.enrich("technologies", technologies)
    self.evidence.log_parsed("reconnaissance", "live_hosts", live_hosts)
    self.logger.info(f"Found {len(live_hosts)} live hosts")
```

Update `_run_httpx()` to strip schemes from stored hosts:
```python
async def _run_httpx(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
    import tempfile, os, json
    fd, input_file = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(subdomains))

    result = self._cmd.run(
        "httpx", ["-l", input_file, "-silent", "-tech-detect", "-status-code", "-json"],
        timeout=600,
    )
    os.unlink(input_file)

    live = []
    techs = []
    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "httpx", result.stdout)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                if url:
                    # Strip scheme, store bare hostname
                    hostname = parse_url_components(url)["hostname"]
                    if hostname:
                        live.append(hostname)
                for tech in entry.get("tech", []):
                    techs.append(tech)
            except json.JSONDecodeError:
                if line.strip():
                    live.append(strip_scheme(line.strip()))
    return live, list(set(techs))
```

Update `_fallback_probe()` to strip schemes:
```python
async def _fallback_probe(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
    import requests
    live = []
    techs = []
    for sub in subdomains:
        for scheme in ["https", "http"]:
            try:
                resp = requests.get(f"{scheme}://{sub}", timeout=10, allow_redirects=True)
                live.append(sub)  # Store bare hostname, not full URL
                server = resp.headers.get("Server", "")
                if server:
                    techs.append(server)
                powered = resp.headers.get("X-Powered-By", "")
                if powered:
                    techs.append(powered)
                break
            except Exception:
                continue
    return live, list(set(techs))
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: All PASS

**Step 5: Update existing tests**

Update `test_subcategories` to include `url_harvesting`:
```python
def test_subcategories(recon_module):
    assert "passive_osint" in recon_module.SUBCATEGORIES
    assert "url_harvesting" in recon_module.SUBCATEGORIES
    assert "live_host_validation" in recon_module.SUBCATEGORIES
    assert "parameter_harvesting" in recon_module.SUBCATEGORIES
```

Update `test_passive_osint_runs_subfinder` — passive_osint no longer calls gau/wayback:
```python
@pytest.mark.asyncio
async def test_passive_osint_runs_subfinder(recon_module):
    with patch.object(recon_module, '_run_subfinder', new_callable=AsyncMock, return_value=["sub.example.com"]):
        await recon_module._passive_osint()
        recon_module.state.enrich.assert_any_call("discovered_subdomains", ["sub.example.com"])
```

**Step 6: Run all tests**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: All PASS

**Step 7: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: reorder recon pipeline, add url_harvesting phase, seed in_scope_urls into live host validation"
```

---

### Task 12: Wire up StateManager scope_checker in Orchestrator

**Files:**
- Modify: `main.py` (wherever StateManager is instantiated)
- Test: verify existing tests still pass

**Step 1: Find where StateManager is instantiated**

Check `main.py` for the `StateManager(...)` constructor call.

**Step 2: Pass scope_checker to StateManager**

After `ConfigLoader` creates the `ScopeChecker`, pass it to `StateManager`:

```python
scope_checker = config.create_scope_checker()
state = StateManager(state_file, target_domain=config.base_domain, company_name=config.company_name, scope_checker=scope_checker)
```

**Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 4: Commit**

```bash
git add main.py
git commit -m "feat: wire scope_checker into StateManager for enrich-time filtering"
```

---

### Task 13: Final integration test and cleanup

**Files:**
- Test: `tests/test_config_loader.py`, `tests/test_reconnaissance.py`

**Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 2: Verify no remaining `*.` prefixes in stored wildcard_urls**

Grep the codebase for any remaining `*. ` patterns that should have been updated:

```bash
grep -rn '\*\.' tests/ wstg_orchestrator/ --include="*.py" | grep -v "fnmatch\|out_of_scope\|__pycache__"
```

**Step 3: Verify no remaining scheme-prefixed URLs in state storage**

Grep for patterns where URLs with schemes are stored in state:

```bash
grep -rn 'enrich.*https\?://' wstg_orchestrator/ --include="*.py"
```

Fix any remaining instances.

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "chore: final cleanup - remove remaining scheme prefixes and wildcard patterns"
```
