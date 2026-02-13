# WSTG Orchestrator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a modular, autonomous OWASP WSTG-aligned security testing orchestration framework with centralized state, scope enforcement, and evidence capture.

**Architecture:** Central orchestrator dispatches testing modules sequentially/in-parallel based on dependency graph. All modules share state via StateManager, scope enforcement via ScopeChecker, and rate-limited HTTP via shared utilities.

**Tech Stack:** Python 3.11+, asyncio, aiohttp, PyYAML, requests, threading, subprocess

**Design Doc:** `docs/plans/2026-02-12-wstg-orchestrator-design.md`

---

## Task 1: Project Scaffold & Dependencies

**Files:**
- Create: `wstg_orchestrator/__init__.py`
- Create: `wstg_orchestrator/modules/__init__.py`
- Create: `wstg_orchestrator/utils/__init__.py`
- Create: `requirements.txt`
- Create: `tests/__init__.py`
- Create: `tests/test_state_manager.py` (empty for now)

**Step 1: Create directory structure**

```bash
mkdir -p wstg_orchestrator/modules wstg_orchestrator/utils tests
```

**Step 2: Create package init files**

Create empty `__init__.py` in `wstg_orchestrator/`, `wstg_orchestrator/modules/`, `wstg_orchestrator/utils/`, and `tests/`.

**Step 3: Create requirements.txt**

```
pyyaml>=6.0
requests>=2.31
aiohttp>=3.9
```

**Step 4: Install dependencies**

```bash
pip install -r requirements.txt
```

**Step 5: Commit**

```bash
git add -A && git commit -m "scaffold: project structure and dependencies"
```

---

## Task 2: State Manager

**Files:**
- Create: `wstg_orchestrator/state_manager.py`
- Create: `tests/test_state_manager.py`

**Step 1: Write failing tests**

```python
# tests/test_state_manager.py
import json
import os
import tempfile
import pytest
from wstg_orchestrator.state_manager import StateManager


@pytest.fixture
def tmp_state_file():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_init_creates_fresh_state(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.get("target_domain") == "example.com"
    assert sm.get("company_name") == "ExCorp"
    assert sm.get("discovered_subdomains") == []
    assert sm.get("scan_id") is not None


def test_enrich_appends_deduplicated(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.enrich("discovered_subdomains", ["a.example.com", "b.example.com"])
    sm.enrich("discovered_subdomains", ["b.example.com", "c.example.com"])
    assert sm.get("discovered_subdomains") == ["a.example.com", "b.example.com", "c.example.com"]


def test_save_and_load(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.enrich("live_hosts", ["h1.example.com"])
    sm.save()
    sm2 = StateManager(tmp_state_file)
    assert sm2.get("live_hosts") == ["h1.example.com"]
    assert sm2.get("target_domain") == "example.com"


def test_mark_subcategory_and_phase_complete(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.mark_subcategory_complete("reconnaissance", "passive_osint")
    phases = sm.get("completed_phases")
    assert phases["reconnaissance"]["subcategories"]["passive_osint"] is True
    assert phases["reconnaissance"]["completed"] is False
    sm.mark_phase_complete("reconnaissance")
    phases = sm.get("completed_phases")
    assert phases["reconnaissance"]["completed"] is True


def test_is_phase_complete(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.is_phase_complete("reconnaissance") is False
    sm.mark_phase_complete("reconnaissance")
    assert sm.is_phase_complete("reconnaissance") is True


def test_is_subcategory_complete(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    assert sm.is_subcategory_complete("reconnaissance", "passive_osint") is False
    sm.mark_subcategory_complete("reconnaissance", "passive_osint")
    assert sm.is_subcategory_complete("reconnaissance", "passive_osint") is True


def test_resume_skips_completed(tmp_state_file):
    sm = StateManager(tmp_state_file, target_domain="example.com", company_name="ExCorp")
    sm.mark_phase_complete("reconnaissance")
    sm.mark_subcategory_complete("fingerprinting", "service_scanning")
    sm.save()
    sm2 = StateManager(tmp_state_file)
    assert sm2.is_phase_complete("reconnaissance") is True
    assert sm2.is_subcategory_complete("fingerprinting", "service_scanning") is True
    assert sm2.is_phase_complete("fingerprinting") is False
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_manager.py -v
```

Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement StateManager**

```python
# wstg_orchestrator/state_manager.py
import json
import os
import threading
import uuid
from datetime import datetime, timezone


class StateManager:
    STATE_KEYS = [
        "target_domain", "company_name", "scan_id", "scan_start",
        "completed_phases", "discovered_subdomains", "live_hosts",
        "open_ports", "technologies", "server_versions", "frameworks",
        "endpoints", "parameters", "forms", "auth_endpoints",
        "api_endpoints", "cloud_assets", "potential_idor_candidates",
        "valid_usernames", "inferred_cves", "exposed_admin_paths",
        "pending_callbacks", "potential_vulnerabilities",
        "confirmed_vulnerabilities", "evidence_index",
    ]

    LIST_KEYS = [
        "discovered_subdomains", "live_hosts", "open_ports",
        "technologies", "server_versions", "frameworks", "endpoints",
        "parameters", "forms", "auth_endpoints", "api_endpoints",
        "cloud_assets", "potential_idor_candidates", "valid_usernames",
        "inferred_cves", "exposed_admin_paths", "pending_callbacks",
        "potential_vulnerabilities", "confirmed_vulnerabilities",
        "evidence_index",
    ]

    def __init__(self, state_file: str, target_domain: str = "", company_name: str = ""):
        self._file = state_file
        self._lock = threading.Lock()
        if os.path.exists(state_file) and os.path.getsize(state_file) > 0:
            with open(state_file, "r") as f:
                self._state = json.load(f)
        else:
            self._state = self._fresh_state(target_domain, company_name)

    def _fresh_state(self, target_domain: str, company_name: str) -> dict:
        state = {
            "target_domain": target_domain,
            "company_name": company_name,
            "scan_id": str(uuid.uuid4()),
            "scan_start": datetime.now(timezone.utc).isoformat(),
            "completed_phases": {},
        }
        for key in self.LIST_KEYS:
            state[key] = []
        return state

    def get(self, key: str):
        with self._lock:
            return self._state.get(key)

    def set(self, key: str, value):
        with self._lock:
            self._state[key] = value

    def enrich(self, key: str, values: list):
        with self._lock:
            existing = self._state.get(key, [])
            for v in values:
                if v not in existing:
                    existing.append(v)
            self._state[key] = existing

    def save(self):
        with self._lock:
            with open(self._file, "w") as f:
                json.dump(self._state, f, indent=2, default=str)

    def mark_subcategory_complete(self, phase: str, subcategory: str):
        with self._lock:
            phases = self._state.setdefault("completed_phases", {})
            phase_data = phases.setdefault(phase, {"completed": False, "subcategories": {}})
            phase_data["subcategories"][subcategory] = True
        self.save()

    def mark_phase_complete(self, phase: str):
        with self._lock:
            phases = self._state.setdefault("completed_phases", {})
            phase_data = phases.setdefault(phase, {"completed": False, "subcategories": {}})
            phase_data["completed"] = True
        self.save()

    def is_phase_complete(self, phase: str) -> bool:
        with self._lock:
            phases = self._state.get("completed_phases", {})
            return phases.get(phase, {}).get("completed", False)

    def is_subcategory_complete(self, phase: str, subcategory: str) -> bool:
        with self._lock:
            phases = self._state.get("completed_phases", {})
            return phases.get(phase, {}).get("subcategories", {}).get(subcategory, False)
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_manager.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/state_manager.py tests/test_state_manager.py
git commit -m "feat: implement StateManager with thread-safe state persistence and resume"
```

---

## Task 3: Config Loader & Scope Checker

**Files:**
- Create: `wstg_orchestrator/utils/scope_checker.py`
- Create: `wstg_orchestrator/utils/config_loader.py`
- Create: `tests/test_scope_checker.py`
- Create: `tests/test_config_loader.py`

**Step 1: Write failing tests for ScopeChecker**

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_scope_checker.py -v
```

**Step 3: Implement ScopeChecker**

```python
# wstg_orchestrator/utils/scope_checker.py
import fnmatch
import re
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    pass


class ScopeChecker:
    def __init__(
        self,
        base_domain: str,
        out_of_scope_urls: list[str] | None = None,
        out_of_scope_ips: list[str] | None = None,
        out_of_scope_attack_vectors: list[str] | None = None,
    ):
        self.base_domain = base_domain.lower()
        self.out_of_scope_urls = [u.lower() for u in (out_of_scope_urls or [])]
        self.out_of_scope_ips = set(out_of_scope_ips or [])
        self.out_of_scope_attack_vectors = set(
            v.lower() for v in (out_of_scope_attack_vectors or [])
        )

    def is_in_scope(self, target: str) -> bool:
        target_lower = target.lower()
        parsed = urlparse(target_lower if "://" in target_lower else f"http://{target_lower}")
        hostname = parsed.hostname or target_lower

        # Check if IP is blacklisted
        if hostname in self.out_of_scope_ips:
            return False

        # Must contain base domain
        if self.base_domain not in target_lower:
            return False

        # Check blacklist (exact and wildcard)
        for oos in self.out_of_scope_urls:
            if fnmatch.fnmatch(hostname, oos):
                return False
            if hostname == oos:
                return False

        return True

    def is_attack_vector_allowed(self, vector: str) -> bool:
        return vector.lower() not in self.out_of_scope_attack_vectors
```

**Step 4: Run scope checker tests**

```bash
pytest tests/test_scope_checker.py -v
```

Expected: All PASS

**Step 5: Write failing tests for ConfigLoader**

```python
# tests/test_config_loader.py
import os
import tempfile
import pytest
import yaml
from wstg_orchestrator.utils.config_loader import ConfigLoader


@pytest.fixture
def sample_config():
    return {
        "program_scope": {
            "company_name": "TestCorp",
            "base_domain": "testcorp.com",
            "wildcard_urls": ["*.testcorp.com"],
            "in_scope_urls": ["app.testcorp.com", "api.testcorp.com"],
            "in_scope_ips": [],
            "out_of_scope_urls": ["admin.testcorp.com"],
            "out_of_scope_ips": ["10.0.0.1"],
            "out_of_scope_attack_vectors": ["dos"],
            "rate_limit": 10,
            "custom_headers": {"X-Bug-Bounty": "testcorp-program"},
            "notes": "No destructive testing",
        },
        "auth_profiles": {
            "default": {
                "type": "bearer",
                "token": "abc123",
            }
        },
        "tool_configs": {
            "nmap": {"flags": "-T3"},
            "gobuster": {"threads": 20},
        },
        "callback_server": {
            "host": "0.0.0.0",
            "port": 8443,
        },
    }


@pytest.fixture
def config_file(sample_config):
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w") as f:
        yaml.dump(sample_config, f)
    yield path
    os.remove(path)


def test_load_config(config_file):
    config = ConfigLoader(config_file)
    assert config.company_name == "TestCorp"
    assert config.base_domain == "testcorp.com"
    assert config.rate_limit == 10


def test_custom_headers(config_file):
    config = ConfigLoader(config_file)
    assert config.custom_headers == {"X-Bug-Bounty": "testcorp-program"}


def test_get_tool_config(config_file):
    config = ConfigLoader(config_file)
    nmap_cfg = config.get_tool_config("nmap")
    assert nmap_cfg["flags"] == "-T3"
    assert config.get_tool_config("unknown_tool") == {}


def test_auth_profile(config_file):
    config = ConfigLoader(config_file)
    profile = config.get_auth_profile("default")
    assert profile["type"] == "bearer"
    assert profile["token"] == "abc123"
    assert config.get_auth_profile("nonexistent") is None


def test_scope_checker_creation(config_file):
    config = ConfigLoader(config_file)
    checker = config.create_scope_checker()
    assert checker.is_in_scope("https://app.testcorp.com") is True
    assert checker.is_in_scope("https://admin.testcorp.com") is False


def test_callback_config(config_file):
    config = ConfigLoader(config_file)
    assert config.callback_host == "0.0.0.0"
    assert config.callback_port == 8443


def test_out_of_scope_attack_vectors(config_file):
    config = ConfigLoader(config_file)
    checker = config.create_scope_checker()
    assert checker.is_attack_vector_allowed("dos") is False
    assert checker.is_attack_vector_allowed("sqli") is True
```

**Step 6: Implement ConfigLoader**

```python
# wstg_orchestrator/utils/config_loader.py
import yaml
from wstg_orchestrator.utils.scope_checker import ScopeChecker


class ConfigLoader:
    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            self._raw = yaml.safe_load(f)
        self._scope = self._raw.get("program_scope", {})
        self._auth = self._raw.get("auth_profiles", {})
        self._tools = self._raw.get("tool_configs", {})
        self._callback = self._raw.get("callback_server", {})

    @property
    def company_name(self) -> str:
        return self._scope.get("company_name", "")

    @property
    def base_domain(self) -> str:
        return self._scope.get("base_domain", "")

    @property
    def rate_limit(self) -> int:
        return self._scope.get("rate_limit", 10)

    @property
    def custom_headers(self) -> dict:
        return self._scope.get("custom_headers", {})

    @property
    def wildcard_urls(self) -> list:
        return self._scope.get("wildcard_urls", [])

    @property
    def in_scope_urls(self) -> list:
        return self._scope.get("in_scope_urls", [])

    @property
    def in_scope_ips(self) -> list:
        return self._scope.get("in_scope_ips", [])

    @property
    def out_of_scope_urls(self) -> list:
        return self._scope.get("out_of_scope_urls", [])

    @property
    def out_of_scope_ips(self) -> list:
        return self._scope.get("out_of_scope_ips", [])

    @property
    def out_of_scope_attack_vectors(self) -> list:
        return self._scope.get("out_of_scope_attack_vectors", [])

    @property
    def notes(self) -> str:
        return self._scope.get("notes", "")

    @property
    def callback_host(self) -> str:
        return self._callback.get("host", "0.0.0.0")

    @property
    def callback_port(self) -> int:
        return self._callback.get("port", 8443)

    def get_tool_config(self, tool_name: str) -> dict:
        return self._tools.get(tool_name, {})

    def get_auth_profile(self, profile_name: str) -> dict | None:
        return self._auth.get(profile_name)

    def create_scope_checker(self) -> ScopeChecker:
        return ScopeChecker(
            base_domain=self.base_domain,
            out_of_scope_urls=self.out_of_scope_urls,
            out_of_scope_ips=self.out_of_scope_ips,
            out_of_scope_attack_vectors=self.out_of_scope_attack_vectors,
        )

    def save(self, path: str):
        with open(path, "w") as f:
            yaml.dump(self._raw, f, default_flow_style=False, sort_keys=False)
```

**Step 7: Run all tests**

```bash
pytest tests/test_scope_checker.py tests/test_config_loader.py -v
```

Expected: All PASS

**Step 8: Commit**

```bash
git add wstg_orchestrator/utils/scope_checker.py wstg_orchestrator/utils/config_loader.py tests/test_scope_checker.py tests/test_config_loader.py
git commit -m "feat: implement ScopeChecker and ConfigLoader with scope enforcement"
```

---

## Task 4: Rate Limiter

**Files:**
- Create: `wstg_orchestrator/utils/rate_limit_handler.py`
- Create: `tests/test_rate_limiter.py`

**Step 1: Write failing tests**

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_rate_limiter.py -v
```

**Step 3: Implement RateLimiter**

```python
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
```

**Step 4: Run tests**

```bash
pytest tests/test_rate_limiter.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/rate_limit_handler.py tests/test_rate_limiter.py
git commit -m "feat: implement adaptive RateLimiter with backoff and passive bypass"
```

---

## Task 5: Command Runner

**Files:**
- Create: `wstg_orchestrator/utils/command_runner.py`
- Create: `tests/test_command_runner.py`

**Step 1: Write failing tests**

```python
# tests/test_command_runner.py
import pytest
from wstg_orchestrator.utils.command_runner import CommandRunner


@pytest.fixture
def runner():
    return CommandRunner(tool_configs={})


def test_check_tool_available(runner):
    assert runner.is_tool_available("echo") is True
    assert runner.is_tool_available("nonexistent_tool_xyz_123") is False


def test_run_command_success(runner):
    result = runner.run("echo", ["hello", "world"], timeout=5)
    assert result.returncode == 0
    assert "hello world" in result.stdout


def test_run_command_timeout(runner):
    result = runner.run("sleep", ["10"], timeout=1)
    assert result.returncode != 0
    assert result.timed_out is True


def test_run_command_with_tool_config():
    runner = CommandRunner(tool_configs={"echo": {"extra_args": ["-n"]}})
    cfg = runner.get_merged_args("echo", ["hello"])
    assert "-n" in cfg


def test_run_command_not_found(runner):
    result = runner.run("nonexistent_tool_xyz_123", [], timeout=5)
    assert result.returncode != 0
    assert result.tool_missing is True
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_command_runner.py -v
```

**Step 3: Implement CommandRunner**

```python
# wstg_orchestrator/utils/command_runner.py
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    tool: str
    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    tool_missing: bool = False


class CommandRunner:
    def __init__(self, tool_configs: dict | None = None):
        self._tool_configs = tool_configs or {}

    def is_tool_available(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    def get_merged_args(self, tool_name: str, args: list[str]) -> list[str]:
        cfg = self._tool_configs.get(tool_name, {})
        extra = cfg.get("extra_args", [])
        flags = cfg.get("flags", "")
        merged = list(args)
        if flags:
            merged = flags.split() + merged
        if extra:
            merged = extra + merged
        return merged

    def run(
        self,
        tool: str,
        args: list[str] | None = None,
        timeout: int = 120,
        cwd: str | None = None,
    ) -> CommandResult:
        args = args or []

        if not self.is_tool_available(tool):
            logger.warning(f"Tool not found: {tool}")
            return CommandResult(
                tool=tool, args=args, returncode=1,
                stderr=f"Tool not found: {tool}", tool_missing=True,
            )

        merged_args = self.get_merged_args(tool, args)
        cmd = [tool] + merged_args

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            return CommandResult(
                tool=tool, args=merged_args,
                returncode=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"Tool timed out after {timeout}s: {tool}")
            return CommandResult(
                tool=tool, args=merged_args,
                returncode=-1, timed_out=True,
                stderr=f"Timed out after {timeout}s",
            )
        except Exception as e:
            logger.error(f"Error running {tool}: {e}")
            return CommandResult(
                tool=tool, args=merged_args,
                returncode=-1, stderr=str(e),
            )
```

**Step 4: Run tests**

```bash
pytest tests/test_command_runner.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/command_runner.py tests/test_command_runner.py
git commit -m "feat: implement CommandRunner with tool availability checks and config merging"
```

---

## Task 6: Evidence Logger

**Files:**
- Create: `wstg_orchestrator/utils/evidence_logger.py`
- Create: `tests/test_evidence_logger.py`

**Step 1: Write failing tests**

```python
# tests/test_evidence_logger.py
import json
import os
import tempfile
import pytest
from wstg_orchestrator.utils.evidence_logger import EvidenceLogger


PHASE_SUBDIRS = {
    "reconnaissance": ["tool_output", "parsed", "evidence", "screenshots"],
    "fingerprinting": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
}


@pytest.fixture
def evidence_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_create_phase_directories(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    company_dir = os.path.join(evidence_dir, "TestCorp")
    assert os.path.isdir(company_dir)
    assert os.path.isdir(os.path.join(company_dir, "reconnaissance", "tool_output"))
    assert os.path.isdir(os.path.join(company_dir, "reports"))


def test_log_tool_output(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    path = el.log_tool_output("reconnaissance", "subfinder", "sub1.example.com\nsub2.example.com")
    assert os.path.exists(path)
    with open(path) as f:
        assert "sub1.example.com" in f.read()


def test_log_parsed(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    data = {"subdomains": ["a.example.com"]}
    path = el.log_parsed("reconnaissance", "subdomains", data)
    assert os.path.exists(path)
    with open(path) as f:
        loaded = json.load(f)
    assert loaded["subdomains"] == ["a.example.com"]


def test_log_request_response(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    req_path = el.log_request("fingerprinting", {"method": "GET", "url": "https://example.com"})
    resp_path = el.log_response("fingerprinting", {"status": 200, "body": "OK"})
    assert os.path.exists(req_path)
    assert os.path.exists(resp_path)


def test_log_potential_exploit(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    finding = {"type": "sqli", "url": "https://example.com/search?q=test", "payload": "' OR 1=1--"}
    path = el.log_potential_exploit("fingerprinting", finding)
    assert os.path.exists(path)


def test_log_confirmed_exploit(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    finding = {"type": "xss", "url": "https://example.com/reflect", "payload": "<script>alert(1)</script>"}
    path = el.log_confirmed_exploit("fingerprinting", finding)
    assert os.path.exists(path)


def test_recon_has_no_raw_requests_dir(evidence_dir):
    el = EvidenceLogger(evidence_dir, "TestCorp", PHASE_SUBDIRS)
    company_dir = os.path.join(evidence_dir, "TestCorp")
    assert not os.path.isdir(os.path.join(company_dir, "reconnaissance", "raw_requests"))
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_evidence_logger.py -v
```

**Step 3: Implement EvidenceLogger**

```python
# wstg_orchestrator/utils/evidence_logger.py
import json
import os
from datetime import datetime, timezone


class EvidenceLogger:
    def __init__(self, base_evidence_dir: str, company_name: str, phase_subdirs: dict[str, list[str]]):
        self._base = os.path.join(base_evidence_dir, company_name)
        self._company = company_name
        self._phase_subdirs = phase_subdirs
        self._setup_directories()

    def _setup_directories(self):
        os.makedirs(self._base, exist_ok=True)
        os.makedirs(os.path.join(self._base, "reports"), exist_ok=True)
        for phase, subdirs in self._phase_subdirs.items():
            for subdir in subdirs:
                os.makedirs(os.path.join(self._base, phase, subdir), exist_ok=True)

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

    def _write_text(self, phase: str, subdir: str, name: str, content: str) -> str:
        path = os.path.join(self._base, phase, subdir, f"{self._timestamp()}_{name}.txt")
        with open(path, "w") as f:
            f.write(content)
        return path

    def _write_json(self, phase: str, subdir: str, name: str, data: dict | list) -> str:
        path = os.path.join(self._base, phase, subdir, f"{self._timestamp()}_{name}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def log_tool_output(self, phase: str, tool_name: str, output: str) -> str:
        return self._write_text(phase, "tool_output", tool_name, output)

    def log_request(self, phase: str, request_data: dict) -> str:
        return self._write_json(phase, "raw_requests", "request", request_data)

    def log_response(self, phase: str, response_data: dict) -> str:
        return self._write_json(phase, "raw_responses", "response", response_data)

    def log_parsed(self, phase: str, data_name: str, data: dict | list) -> str:
        return self._write_json(phase, "parsed", data_name, data)

    def log_potential_exploit(self, phase: str, finding: dict) -> str:
        return self._write_json(phase, "potential_exploits", "potential", finding)

    def log_confirmed_exploit(self, phase: str, finding: dict) -> str:
        return self._write_json(phase, "confirmed_exploits", "confirmed", finding)

    def log_screenshot(self, phase: str, name: str, image_data: bytes) -> str:
        path = os.path.join(self._base, phase, "screenshots", f"{self._timestamp()}_{name}.png")
        with open(path, "wb") as f:
            f.write(image_data)
        return path

    def get_reports_dir(self) -> str:
        return os.path.join(self._base, "reports")
```

**Step 4: Run tests**

```bash
pytest tests/test_evidence_logger.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/evidence_logger.py tests/test_evidence_logger.py
git commit -m "feat: implement EvidenceLogger with per-phase directory structure"
```

---

## Task 7: HTTP Utils

**Files:**
- Create: `wstg_orchestrator/utils/http_utils.py`
- Create: `tests/test_http_utils.py`

**Step 1: Write failing tests**

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_http_utils.py -v
```

**Step 3: Implement HttpClient**

```python
# wstg_orchestrator/utils/http_utils.py
import logging
from dataclasses import dataclass, field
import requests as req_lib

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
        self._session = req_lib.Session()
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
```

**Step 4: Run tests**

```bash
pytest tests/test_http_utils.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/http_utils.py tests/test_http_utils.py
git commit -m "feat: implement HttpClient with scope enforcement, rate limiting, and custom headers"
```

---

## Task 8: Parser Utils

**Files:**
- Create: `wstg_orchestrator/utils/parser_utils.py`
- Create: `tests/test_parser_utils.py`

**Step 1: Write failing tests**

```python
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
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_parser_utils.py -v
```

**Step 3: Implement parser_utils**

```python
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
```

**Step 4: Run tests**

```bash
pytest tests/test_parser_utils.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/parser_utils.py tests/test_parser_utils.py
git commit -m "feat: implement parser utils for URL extraction, form parsing, and ID detection"
```

---

## Task 9: Callback Server

**Files:**
- Create: `wstg_orchestrator/utils/callback_server.py`
- Create: `tests/test_callback_server.py`

**Step 1: Write failing tests**

```python
# tests/test_callback_server.py
import asyncio
import threading
import time
import pytest
import requests
from wstg_orchestrator.utils.callback_server import CallbackServer


@pytest.fixture
def server():
    srv = CallbackServer(host="127.0.0.1", port=0)  # port=0 for random available port
    srv.start()
    time.sleep(0.3)
    yield srv
    srv.stop()


def test_generate_callback_url(server):
    url, token = server.generate_callback(
        module="input_validation",
        parameter="q",
        payload="<script>fetch(CALLBACK)</script>",
    )
    assert token in url
    assert server.host in url or "127.0.0.1" in url


def test_callback_hit_recorded(server):
    url, token = server.generate_callback(
        module="input_validation",
        parameter="q",
        payload="test_payload",
    )
    requests.get(url, timeout=5)
    time.sleep(0.3)
    hits = server.get_hits()
    assert len(hits) >= 1
    assert hits[0]["token"] == token
    assert hits[0]["module"] == "input_validation"


def test_pending_callbacks_tracked(server):
    _, token = server.generate_callback(
        module="recon", parameter="x", payload="p",
    )
    pending = server.get_pending()
    assert any(p["token"] == token for p in pending)


def test_hit_moves_from_pending(server):
    url, token = server.generate_callback(
        module="recon", parameter="x", payload="p",
    )
    requests.get(url, timeout=5)
    time.sleep(0.3)
    pending = server.get_pending()
    assert not any(p["token"] == token for p in pending)
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_callback_server.py -v
```

**Step 3: Implement CallbackServer**

```python
# wstg_orchestrator/utils/callback_server.py
import json
import logging
import socket
import threading
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class CallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8443, external_url: str | None = None):
        self.host = host
        self.port = port
        self._external_url = external_url
        self._pending: dict[str, dict] = {}
        self._hits: list[dict] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                token = self.path.strip("/").split("/")[-1].split("?")[0]
                server_ref._record_hit(token, self)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                token = self.path.strip("/").split("/")[-1].split("?")[0]
                server_ref._record_hit(token, self, body=body)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format, *args):
                logger.debug(f"Callback server: {format % args}")

        self._server = HTTPServer((self.host, self.port), Handler)
        if self.port == 0:
            self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"Callback server started on {self.host}:{self.port}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None

    def generate_callback(self, module: str, parameter: str, payload: str) -> tuple[str, str]:
        token = str(uuid.uuid4()).replace("-", "")[:16]
        base = self._external_url or f"http://{self._get_host()}:{self.port}"
        url = f"{base}/{token}"
        entry = {
            "token": token,
            "module": module,
            "parameter": parameter,
            "payload": payload,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._pending[token] = entry
        return url, token

    def _get_host(self) -> str:
        if self.host == "0.0.0.0":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                return "127.0.0.1"
        return self.host

    def _record_hit(self, token: str, handler, body: str | None = None):
        with self._lock:
            pending = self._pending.pop(token, None)
            hit = {
                "token": token,
                "module": pending["module"] if pending else "unknown",
                "parameter": pending["parameter"] if pending else "unknown",
                "payload": pending["payload"] if pending else "unknown",
                "source_ip": handler.client_address[0],
                "method": handler.command,
                "path": handler.path,
                "headers": dict(handler.headers),
                "body": body,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._hits.append(hit)
            logger.info(f"Callback hit! Token: {token}, Module: {hit['module']}")

    def get_hits(self) -> list[dict]:
        with self._lock:
            return list(self._hits)

    def get_pending(self) -> list[dict]:
        with self._lock:
            return list(self._pending.values())
```

**Step 4: Run tests**

```bash
pytest tests/test_callback_server.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/callback_server.py tests/test_callback_server.py
git commit -m "feat: implement CallbackServer for blind exploit confirmation"
```

---

## Task 10: Interactive Scope Builder

**Files:**
- Create: `wstg_orchestrator/scope_builder.py`
- Create: `tests/test_scope_builder.py`

**Step 1: Write failing tests**

```python
# tests/test_scope_builder.py
import os
import tempfile
import pytest
import yaml
from unittest.mock import patch
from wstg_orchestrator.scope_builder import ScopeBuilder


def test_build_config_from_inputs():
    inputs = iter([
        "TestCorp",                          # company name
        "testcorp.com",                      # base domain
        "app.testcorp.com, api.testcorp.com",# in-scope urls
        "",                                  # in-scope ips
        "admin.testcorp.com",                # out-of-scope urls
        "10.0.0.1",                          # out-of-scope ips
        "dos, social_engineering",           # out-of-scope attack vectors
        "10",                                # rate limit
        "X-Bug-Bounty: testcorp-123",        # custom headers
        "",                                  # auth profiles (skip)
        "",                                  # callback host (default)
        "",                                  # callback port (default)
        "No destructive testing allowed",    # notes
    ])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        builder = ScopeBuilder()
        config = builder.build()

    assert config["program_scope"]["company_name"] == "TestCorp"
    assert config["program_scope"]["base_domain"] == "testcorp.com"
    assert "app.testcorp.com" in config["program_scope"]["in_scope_urls"]
    assert "admin.testcorp.com" in config["program_scope"]["out_of_scope_urls"]
    assert "dos" in config["program_scope"]["out_of_scope_attack_vectors"]
    assert config["program_scope"]["rate_limit"] == 10
    assert config["program_scope"]["custom_headers"]["X-Bug-Bounty"] == "testcorp-123"


def test_save_config():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "config.yaml")
        config_data = {
            "program_scope": {"company_name": "Test", "base_domain": "test.com"},
        }
        ScopeBuilder.save_config(config_data, path)
        assert os.path.exists(path)
        with open(path) as f:
            loaded = yaml.safe_load(f)
        assert loaded["program_scope"]["company_name"] == "Test"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_scope_builder.py -v
```

**Step 3: Implement ScopeBuilder**

```python
# wstg_orchestrator/scope_builder.py
import yaml


class ScopeBuilder:
    def build(self) -> dict:
        print("\n=== WSTG Orchestrator - Scope Builder ===\n")

        company_name = input("Company name: ").strip()
        base_domain = input("Base domain (e.g., example.com): ").strip()

        in_scope_urls = self._parse_list(
            input("In-scope URLs (comma-separated, or empty): ")
        )
        in_scope_ips = self._parse_list(
            input("In-scope IPs (comma-separated, or empty): ")
        )
        out_of_scope_urls = self._parse_list(
            input("Out-of-scope URLs (comma-separated, or empty): ")
        )
        out_of_scope_ips = self._parse_list(
            input("Out-of-scope IPs (comma-separated, or empty): ")
        )
        out_of_scope_attack_vectors = self._parse_list(
            input("Out-of-scope attack vectors (e.g., dos, social_engineering): ")
        )

        rate_limit_raw = input("Rate limit (requests/sec, default 10): ").strip()
        rate_limit = int(rate_limit_raw) if rate_limit_raw else 10

        headers_raw = input("Custom headers (Key: Value, comma-separated, or empty): ").strip()
        custom_headers = self._parse_headers(headers_raw)

        auth_raw = input("Auth profile (type:credential, or empty to skip): ").strip()
        auth_profiles = {}
        if auth_raw:
            auth_profiles = self._parse_auth(auth_raw)

        callback_host = input("Callback server host (default 0.0.0.0): ").strip() or "0.0.0.0"
        callback_port_raw = input("Callback server port (default 8443): ").strip()
        callback_port = int(callback_port_raw) if callback_port_raw else 8443

        notes = input("Additional notes: ").strip()

        return {
            "program_scope": {
                "company_name": company_name,
                "base_domain": base_domain,
                "wildcard_urls": [f"*.{base_domain}"],
                "in_scope_urls": in_scope_urls,
                "in_scope_ips": in_scope_ips,
                "out_of_scope_urls": out_of_scope_urls,
                "out_of_scope_ips": out_of_scope_ips,
                "out_of_scope_attack_vectors": out_of_scope_attack_vectors,
                "rate_limit": rate_limit,
                "custom_headers": custom_headers,
                "notes": notes,
            },
            "auth_profiles": auth_profiles,
            "tool_configs": {},
            "callback_server": {
                "host": callback_host,
                "port": callback_port,
            },
        }

    def _parse_list(self, raw: str) -> list[str]:
        if not raw.strip():
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _parse_headers(self, raw: str) -> dict:
        if not raw:
            return {}
        headers = {}
        for item in raw.split(","):
            if ":" in item:
                key, value = item.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers

    def _parse_auth(self, raw: str) -> dict:
        if ":" in raw:
            auth_type, credential = raw.split(":", 1)
            return {
                "default": {
                    "type": auth_type.strip(),
                    "token": credential.strip(),
                }
            }
        return {}

    @staticmethod
    def save_config(config: dict, path: str):
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
```

**Step 4: Run tests**

```bash
pytest tests/test_scope_builder.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/scope_builder.py tests/test_scope_builder.py
git commit -m "feat: implement interactive ScopeBuilder for config.yaml generation"
```

---

## Task 11: Module Base Interface

**Files:**
- Create: `wstg_orchestrator/modules/base_module.py`
- Create: `tests/test_base_module.py`

**Step 1: Write failing tests**

```python
# tests/test_base_module.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.base_module import BaseModule


class DummyModule(BaseModule):
    PHASE_NAME = "test_phase"
    SUBCATEGORIES = ["sub_a", "sub_b"]
    EVIDENCE_SUBDIRS = ["tool_output", "parsed"]

    async def execute(self):
        self.state.enrich("endpoints", ["https://example.com/test"])
        self.mark_subcategory_complete("sub_a")
        self.mark_subcategory_complete("sub_b")


def test_module_has_required_attrs():
    assert hasattr(BaseModule, "PHASE_NAME")
    assert hasattr(BaseModule, "SUBCATEGORIES")


def test_module_interface():
    state = MagicMock()
    config = MagicMock()
    scope = MagicMock()
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()

    mod = DummyModule(state, config, scope, limiter, evidence, callback)
    assert mod.PHASE_NAME == "test_phase"


def test_skip_completed_subcategory():
    state = MagicMock()
    state.is_subcategory_complete.return_value = True
    config = MagicMock()
    scope = MagicMock()
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()

    mod = DummyModule(state, config, scope, limiter, evidence, callback)
    assert mod.should_skip_subcategory("sub_a") is True


def test_attack_vector_check():
    state = MagicMock()
    config = MagicMock()
    scope = MagicMock()
    scope.is_attack_vector_allowed.return_value = False
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()

    mod = DummyModule(state, config, scope, limiter, evidence, callback)
    assert mod.is_attack_allowed("dos") is False
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_base_module.py -v
```

**Step 3: Implement BaseModule**

```python
# wstg_orchestrator/modules/base_module.py
import logging
from abc import ABC, abstractmethod

from wstg_orchestrator.state_manager import StateManager
from wstg_orchestrator.utils.config_loader import ConfigLoader
from wstg_orchestrator.utils.scope_checker import ScopeChecker
from wstg_orchestrator.utils.rate_limit_handler import RateLimiter
from wstg_orchestrator.utils.evidence_logger import EvidenceLogger
from wstg_orchestrator.utils.callback_server import CallbackServer


class BaseModule(ABC):
    PHASE_NAME: str = ""
    SUBCATEGORIES: list[str] = []
    EVIDENCE_SUBDIRS: list[str] = []

    def __init__(
        self,
        state: StateManager,
        config: ConfigLoader,
        scope_checker: ScopeChecker,
        rate_limiter: RateLimiter,
        evidence_logger: EvidenceLogger,
        callback_server: CallbackServer,
    ):
        self.state = state
        self.config = config
        self.scope = scope_checker
        self.rate_limiter = rate_limiter
        self.evidence = evidence_logger
        self.callback = callback_server
        self.logger = logging.getLogger(f"wstg.{self.PHASE_NAME}")

    @abstractmethod
    async def execute(self):
        pass

    async def run(self):
        if self.state.is_phase_complete(self.PHASE_NAME):
            self.logger.info(f"Phase {self.PHASE_NAME} already complete, skipping")
            return
        self.logger.info(f"Starting phase: {self.PHASE_NAME}")
        await self.execute()
        self.state.mark_phase_complete(self.PHASE_NAME)
        self.logger.info(f"Completed phase: {self.PHASE_NAME}")

    def should_skip_subcategory(self, subcategory: str) -> bool:
        return self.state.is_subcategory_complete(self.PHASE_NAME, subcategory)

    def mark_subcategory_complete(self, subcategory: str):
        self.state.mark_subcategory_complete(self.PHASE_NAME, subcategory)

    def is_attack_allowed(self, vector: str) -> bool:
        return self.scope.is_attack_vector_allowed(vector)
```

**Step 4: Run tests**

```bash
pytest tests/test_base_module.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/base_module.py tests/test_base_module.py
git commit -m "feat: implement BaseModule ABC with resume, scope, and attack vector checks"
```

---

## Task 12: Main Orchestrator

**Files:**
- Create: `wstg_orchestrator/main.py`
- Create: `tests/test_main.py`

**Step 1: Write failing tests**

```python
# tests/test_main.py
import os
import tempfile
import pytest
import yaml
from unittest.mock import patch, MagicMock, AsyncMock
from wstg_orchestrator.main import Orchestrator


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def config_file(tmp_dir):
    config = {
        "program_scope": {
            "company_name": "TestCorp",
            "base_domain": "testcorp.com",
            "wildcard_urls": ["*.testcorp.com"],
            "in_scope_urls": [],
            "in_scope_ips": [],
            "out_of_scope_urls": [],
            "out_of_scope_ips": [],
            "out_of_scope_attack_vectors": [],
            "rate_limit": 50,
            "custom_headers": {},
            "notes": "",
        },
        "auth_profiles": {},
        "tool_configs": {},
        "callback_server": {"host": "127.0.0.1", "port": 0},
    }
    path = os.path.join(tmp_dir, "config.yaml")
    with open(path, "w") as f:
        yaml.dump(config, f)
    return path


def test_orchestrator_init(config_file, tmp_dir):
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    assert orch.config.company_name == "TestCorp"
    assert orch.state.get("target_domain") == "testcorp.com"


def test_orchestrator_creates_evidence_dir(config_file, tmp_dir):
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    assert os.path.isdir(os.path.join(tmp_dir, "evidence", "TestCorp"))


def test_orchestrator_module_order(config_file, tmp_dir):
    orch = Orchestrator(
        config_path=config_file,
        state_path=os.path.join(tmp_dir, "state.json"),
        evidence_dir=os.path.join(tmp_dir, "evidence"),
    )
    order = orch.get_execution_order()
    assert order[0] == "reconnaissance"
    assert "fingerprinting" in order
    assert order.index("reconnaissance") < order.index("input_validation")
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_main.py -v
```

**Step 3: Implement Orchestrator**

```python
# wstg_orchestrator/main.py
import argparse
import asyncio
import logging
import os
import sys

from wstg_orchestrator.state_manager import StateManager
from wstg_orchestrator.utils.config_loader import ConfigLoader
from wstg_orchestrator.utils.scope_checker import ScopeChecker
from wstg_orchestrator.utils.rate_limit_handler import RateLimiter
from wstg_orchestrator.utils.evidence_logger import EvidenceLogger
from wstg_orchestrator.utils.callback_server import CallbackServer
from wstg_orchestrator.utils.command_runner import CommandRunner
from wstg_orchestrator.scope_builder import ScopeBuilder

logger = logging.getLogger("wstg.orchestrator")

PHASE_EVIDENCE_SUBDIRS = {
    "reconnaissance": ["tool_output", "parsed", "evidence", "screenshots"],
    "fingerprinting": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "configuration_testing": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "auth_testing": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "authorization_testing": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "session_testing": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "input_validation": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "business_logic": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
    "api_testing": [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ],
}

EXECUTION_ORDER = [
    "reconnaissance",
    "fingerprinting",
    "configuration_testing",
    "auth_testing",
    "authorization_testing",
    "session_testing",
    "input_validation",
    "business_logic",
    "api_testing",
]

# Phases that can run in parallel (after their dependency completes)
PARALLEL_GROUPS = [
    ["fingerprinting", "configuration_testing"],
    ["authorization_testing", "session_testing"],
]


class Orchestrator:
    def __init__(
        self,
        config_path: str,
        state_path: str = "state.json",
        evidence_dir: str = "evidence",
    ):
        self.config = ConfigLoader(config_path)
        self.state = StateManager(
            state_path,
            target_domain=self.config.base_domain,
            company_name=self.config.company_name,
        )
        self.scope_checker = self.config.create_scope_checker()
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.rate_limit,
            base_domain=self.config.base_domain,
        )
        self.evidence_logger = EvidenceLogger(
            evidence_dir, self.config.company_name, PHASE_EVIDENCE_SUBDIRS,
        )
        self.callback_server = CallbackServer(
            host=self.config.callback_host,
            port=self.config.callback_port,
        )
        self.command_runner = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["nmap", "subfinder", "amass", "gau", "httpx",
                             "gobuster", "whatweb", "sqlmap", "commix",
                             "kiterunner"]
            }
        )
        self._modules = {}

    def get_execution_order(self) -> list[str]:
        return list(EXECUTION_ORDER)

    def _check_tools(self):
        tools = [
            "nmap", "subfinder", "amass", "gau", "httpx",
            "gobuster", "whatweb", "sqlmap", "commix",
        ]
        for tool in tools:
            if self.command_runner.is_tool_available(tool):
                logger.info(f"Tool available: {tool}")
            else:
                logger.warning(f"Tool not found: {tool} (will use fallback if available)")

    async def run(self):
        logger.info(f"Starting WSTG scan for {self.config.company_name}")
        logger.info(f"Target domain: {self.config.base_domain}")

        self._check_tools()
        self.callback_server.start()

        try:
            for phase_name in EXECUTION_ORDER:
                if self.state.is_phase_complete(phase_name):
                    logger.info(f"Skipping completed phase: {phase_name}")
                    continue

                module = self._get_module(phase_name)
                if module:
                    await module.run()
                else:
                    logger.warning(f"No module registered for phase: {phase_name}")
        finally:
            self.callback_server.stop()
            self.state.save()
            logger.info("Scan complete")

    def _get_module(self, phase_name: str):
        return self._modules.get(phase_name)

    def register_module(self, phase_name: str, module):
        self._modules[phase_name] = module


def main():
    parser = argparse.ArgumentParser(description="WSTG Orchestrator")
    parser.add_argument("-c", "--config", default="config.yaml", help="Config file path")
    parser.add_argument("-s", "--state", default="state.json", help="State file path")
    parser.add_argument("-e", "--evidence", default="evidence", help="Evidence directory")
    parser.add_argument("--new", action="store_true", help="Run interactive scope builder")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.new or not os.path.exists(args.config):
        builder = ScopeBuilder()
        config_data = builder.build()
        ScopeBuilder.save_config(config_data, args.config)
        logger.info(f"Config saved to {args.config}")

    orch = Orchestrator(
        config_path=args.config,
        state_path=args.state,
        evidence_dir=args.evidence,
    )

    # TODO: Register actual modules here as they are implemented
    # from wstg_orchestrator.modules.reconnaissance import ReconModule
    # orch.register_module("reconnaissance", ReconModule(orch.state, orch.config, ...))

    asyncio.run(orch.run())


if __name__ == "__main__":
    main()
```

**Step 4: Run tests**

```bash
pytest tests/test_main.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/main.py tests/test_main.py
git commit -m "feat: implement main Orchestrator with phase execution, resume, and CLI"
```

---

## Task 13: Reconnaissance Module

**Files:**
- Create: `wstg_orchestrator/modules/reconnaissance.py`
- Create: `tests/test_reconnaissance.py`

**Step 1: Write failing tests**

```python
# tests/test_reconnaissance.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.reconnaissance import ReconModule


@pytest.fixture
def recon_module():
    state = MagicMock()
    state.get.return_value = []
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    callback = MagicMock()
    return ReconModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(recon_module):
    assert recon_module.PHASE_NAME == "reconnaissance"


def test_subcategories(recon_module):
    assert "passive_osint" in recon_module.SUBCATEGORIES
    assert "live_host_validation" in recon_module.SUBCATEGORIES
    assert "parameter_harvesting" in recon_module.SUBCATEGORIES


@pytest.mark.asyncio
async def test_passive_osint_runs_subfinder(recon_module):
    with patch.object(recon_module, '_run_subfinder', new_callable=AsyncMock, return_value=["sub.example.com"]):
        with patch.object(recon_module, '_run_gau', new_callable=AsyncMock, return_value=[]):
            with patch.object(recon_module, '_run_wayback', new_callable=AsyncMock, return_value=[]):
                await recon_module._passive_osint()
                recon_module.state.enrich.assert_any_call("discovered_subdomains", ["sub.example.com"])


@pytest.mark.asyncio
async def test_scope_filter_applied(recon_module):
    recon_module.scope.is_in_scope.side_effect = lambda url: "example.com" in url
    filtered = recon_module._filter_in_scope(["a.example.com", "evil.com"])
    assert filtered == ["a.example.com"]
```

**Step 2: Run tests to verify they fail**

```bash
pip install pytest-asyncio && pytest tests/test_reconnaissance.py -v
```

**Step 3: Implement ReconModule**

```python
# wstg_orchestrator/modules/reconnaissance.py
import asyncio
import re
from urllib.parse import urlparse, parse_qs

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner
from wstg_orchestrator.utils.parser_utils import (
    extract_params_from_url,
    extract_urls_from_text,
    detect_id_patterns,
)


class ReconModule(BaseModule):
    PHASE_NAME = "reconnaissance"
    SUBCATEGORIES = ["passive_osint", "live_host_validation", "parameter_harvesting"]
    EVIDENCE_SUBDIRS = ["tool_output", "parsed", "evidence", "screenshots"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["subfinder", "amass", "gau", "httpx"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("passive_osint"):
            await self._passive_osint()
            self.mark_subcategory_complete("passive_osint")

        if not self.should_skip_subcategory("live_host_validation"):
            await self._live_host_validation()
            self.mark_subcategory_complete("live_host_validation")

        if not self.should_skip_subcategory("parameter_harvesting"):
            await self._parameter_harvesting()
            self.mark_subcategory_complete("parameter_harvesting")

    async def _passive_osint(self):
        self.logger.info("Starting passive OSINT")
        all_subdomains = []

        subfinder_results = await self._run_subfinder()
        all_subdomains.extend(subfinder_results)

        gau_results = await self._run_gau()
        wayback_results = await self._run_wayback()
        all_urls = gau_results + wayback_results

        # Extract subdomains from URLs
        for url in all_urls:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            if parsed.hostname:
                all_subdomains.append(parsed.hostname)

        all_subdomains = list(set(self._filter_in_scope(all_subdomains)))
        all_urls = list(set(self._filter_in_scope(all_urls)))

        self.state.enrich("discovered_subdomains", all_subdomains)
        self.state.enrich("endpoints", all_urls)
        self.evidence.log_parsed("reconnaissance", "subdomains", all_subdomains)
        self.evidence.log_parsed("reconnaissance", "historical_urls", all_urls)
        self.logger.info(f"Found {len(all_subdomains)} subdomains, {len(all_urls)} URLs")

    async def _run_subfinder(self) -> list[str]:
        result = self._cmd.run(
            "subfinder", ["-d", self.config.base_domain, "-silent"], timeout=300,
        )
        if result.tool_missing:
            self.logger.warning("subfinder not found, trying amass")
            return await self._run_amass()
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "subfinder", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_amass(self) -> list[str]:
        result = self._cmd.run(
            "amass", ["enum", "-passive", "-d", self.config.base_domain], timeout=600,
        )
        if result.tool_missing:
            self.logger.warning("amass not found, skipping subdomain enumeration tools")
            return []
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "amass", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_gau(self) -> list[str]:
        result = self._cmd.run(
            "gau", [self.config.base_domain, "--subs"], timeout=300,
        )
        if result.tool_missing:
            self.logger.warning("gau not found, skipping URL harvesting from gau")
            return []
        if result.returncode == 0:
            self.evidence.log_tool_output("reconnaissance", "gau", result.stdout)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []

    async def _run_wayback(self) -> list[str]:
        # Wayback Machine CDX API - no external tool needed
        try:
            from wstg_orchestrator.utils.http_utils import HttpClient
            # Use raw requests to avoid scope check on archive.org
            import requests
            resp = requests.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{self.config.base_domain}/*&output=text&fl=original&collapse=urlkey",
                timeout=60,
            )
            if resp.status_code == 200:
                urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
                self.evidence.log_tool_output("reconnaissance", "wayback", resp.text)
                return urls
        except Exception as e:
            self.logger.warning(f"Wayback fetch failed: {e}")
        return []

    async def _live_host_validation(self):
        self.logger.info("Starting live host validation")
        subdomains = self.state.get("discovered_subdomains") or []
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

    async def _run_httpx(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
        import tempfile, os
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
            import json
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    url = entry.get("url", "")
                    if url:
                        live.append(url)
                    for tech in entry.get("tech", []):
                        techs.append(tech)
                except json.JSONDecodeError:
                    if line.strip():
                        live.append(line.strip())
        return live, list(set(techs))

    async def _fallback_probe(self, subdomains: list[str]) -> tuple[list[str], list[str]]:
        import requests
        live = []
        techs = []
        for sub in subdomains:
            for scheme in ["https", "http"]:
                try:
                    resp = requests.get(f"{scheme}://{sub}", timeout=10, allow_redirects=True)
                    live.append(f"{scheme}://{sub}")
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

    async def _parameter_harvesting(self):
        self.logger.info("Starting parameter harvesting")
        endpoints = self.state.get("endpoints") or []
        live_hosts = self.state.get("live_hosts") or []

        all_params = []
        idor_candidates = []

        # Extract params from known URLs
        for url in endpoints:
            params = extract_params_from_url(url)
            for name, value in params.items():
                all_params.append({"url": url, "name": name, "value": value, "method": "GET"})

        # Detect ID patterns
        id_patterns = detect_id_patterns(endpoints + live_hosts)
        for pattern in id_patterns:
            idor_candidates.append(pattern)

        # TODO: JS file parsing for hidden endpoints
        # TODO: Form extraction from live hosts

        self.state.enrich("parameters", all_params)
        self.state.enrich("potential_idor_candidates", idor_candidates)
        self.evidence.log_parsed("reconnaissance", "parameters", all_params)
        self.evidence.log_parsed("reconnaissance", "idor_candidates", idor_candidates)
        self.logger.info(f"Found {len(all_params)} parameters, {len(idor_candidates)} IDOR candidates")

    def _filter_in_scope(self, items: list[str]) -> list[str]:
        return [item for item in items if self.scope.is_in_scope(item)]
```

**Step 4: Run tests**

```bash
pytest tests/test_reconnaissance.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: implement ReconModule with subdomain enum, live probing, and param harvesting"
```

---

## Task 14-21: Remaining Modules (Skeleton + Core Logic)

Tasks 14-21 follow the same pattern as Task 13. Each module:
1. Extends `BaseModule`
2. Implements `execute()` with subcategory checks
3. Reads from state, enriches state
4. Logs evidence
5. Has tests with mocked dependencies

**These are listed as individual tasks for execution but share the same structure. Implement in order:**

- **Task 14:** `fingerprinting.py` — nmap XML parse, WhatWeb, header analysis, CVE lookup
- **Task 15:** `configuration_testing.py` — robots/sitemap, gobuster, 403 bypass, HTTP methods, cloud enum
- **Task 16:** `auth_testing.py` — username enum, default creds, lockout detection
- **Task 17:** `authorization_testing.py` — IDOR fuzzing, JWT testing, hidden field tampering
- **Task 18:** `session_testing.py` — cookie flags, fixation, reuse, rotation
- **Task 19:** `input_validation.py` — SQLi/XSS/CMDi probes with tool handoff
- **Task 20:** `business_logic.py` — workflow skip, price tamper, race conditions
- **Task 21:** `api_testing.py` — Swagger detection, BOLA, GraphQL introspection

Each task follows the same step pattern:
1. Write failing tests
2. Run to confirm failure
3. Implement module
4. Run to confirm pass
5. Commit

---

## Task 22: Reporting Engine

**Files:**
- Create: `wstg_orchestrator/reporting.py`
- Create: `tests/test_reporting.py`

**Step 1: Write failing tests**

```python
# tests/test_reporting.py
import json
import os
import tempfile
import pytest
from wstg_orchestrator.reporting import ReportGenerator


@pytest.fixture
def sample_state():
    return {
        "target_domain": "example.com",
        "company_name": "ExCorp",
        "scan_id": "test-123",
        "scan_start": "2026-02-12T00:00:00Z",
        "discovered_subdomains": ["a.example.com", "b.example.com"],
        "live_hosts": ["https://a.example.com"],
        "open_ports": [{"host": "a.example.com", "port": 443}],
        "technologies": ["nginx", "React"],
        "endpoints": ["https://a.example.com/api/users"],
        "parameters": [{"url": "https://a.example.com/search", "name": "q", "method": "GET"}],
        "potential_vulnerabilities": [
            {"type": "xss", "url": "https://a.example.com/search?q=test", "severity": "high",
             "description": "Reflected XSS", "evidence_file": "/evidence/xss.json"},
        ],
        "confirmed_vulnerabilities": [
            {"type": "sqli", "url": "https://a.example.com/api/users?id=1", "severity": "critical",
             "description": "SQL Injection", "evidence_file": "/evidence/sqli.json",
             "reproduction_steps": "1. Send payload ' OR 1=1-- to id param",
             "impact": "Full database access", "mitigation": "Use parameterized queries"},
        ],
        "evidence_index": [],
    }


@pytest.fixture
def reports_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_generate_attack_surface(sample_state, reports_dir):
    gen = ReportGenerator(sample_state, reports_dir)
    gen.generate_attack_surface()
    path = os.path.join(reports_dir, "attack_surface.json")
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert "a.example.com" in data["subdomains"]


def test_generate_findings(sample_state, reports_dir):
    gen = ReportGenerator(sample_state, reports_dir)
    gen.generate_potential_findings()
    gen.generate_confirmed_findings()
    assert os.path.exists(os.path.join(reports_dir, "potential_findings.json"))
    assert os.path.exists(os.path.join(reports_dir, "confirmed_findings.json"))


def test_generate_executive_summary(sample_state, reports_dir):
    gen = ReportGenerator(sample_state, reports_dir)
    gen.generate_executive_summary()
    path = os.path.join(reports_dir, "executive_summary.txt")
    assert os.path.exists(path)
    with open(path) as f:
        content = f.read()
    assert "ExCorp" in content
    assert "CRITICAL" in content.upper() or "SQL Injection" in content
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_reporting.py -v
```

**Step 3: Implement ReportGenerator**

```python
# wstg_orchestrator/reporting.py
import json
import os
from datetime import datetime, timezone


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportGenerator:
    def __init__(self, state: dict, reports_dir: str):
        self._state = state
        self._dir = reports_dir
        os.makedirs(self._dir, exist_ok=True)

    def _write_json(self, filename: str, data: dict | list):
        path = os.path.join(self._dir, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def generate_attack_surface(self) -> str:
        data = {
            "target_domain": self._state.get("target_domain", ""),
            "scan_id": self._state.get("scan_id", ""),
            "subdomains": self._state.get("discovered_subdomains", []),
            "live_hosts": self._state.get("live_hosts", []),
            "open_ports": self._state.get("open_ports", []),
            "technologies": self._state.get("technologies", []),
            "frameworks": self._state.get("frameworks", []),
            "endpoints": self._state.get("endpoints", []),
            "parameters": self._state.get("parameters", []),
            "api_endpoints": self._state.get("api_endpoints", []),
            "cloud_assets": self._state.get("cloud_assets", []),
        }
        return self._write_json("attack_surface.json", data)

    def generate_potential_findings(self) -> str:
        findings = sorted(
            self._state.get("potential_vulnerabilities", []),
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4),
        )
        return self._write_json("potential_findings.json", findings)

    def generate_confirmed_findings(self) -> str:
        findings = sorted(
            self._state.get("confirmed_vulnerabilities", []),
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4),
        )
        return self._write_json("confirmed_findings.json", findings)

    def generate_evidence_index(self) -> str:
        return self._write_json("evidence_index.json", self._state.get("evidence_index", []))

    def generate_executive_summary(self) -> str:
        potential = self._state.get("potential_vulnerabilities", [])
        confirmed = self._state.get("confirmed_vulnerabilities", [])
        all_findings = confirmed + potential

        severity_counts = {}
        for f in all_findings:
            sev = f.get("severity", "info").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines = [
            "=" * 70,
            "EXECUTIVE SUMMARY - SECURITY ASSESSMENT REPORT",
            "=" * 70,
            "",
            f"Company: {self._state.get('company_name', 'N/A')}",
            f"Target: {self._state.get('target_domain', 'N/A')}",
            f"Scan ID: {self._state.get('scan_id', 'N/A')}",
            f"Scan Start: {self._state.get('scan_start', 'N/A')}",
            f"Report Generated: {datetime.now(timezone.utc).isoformat()}",
            "",
            "-" * 70,
            "SCOPE SUMMARY",
            "-" * 70,
            f"Subdomains discovered: {len(self._state.get('discovered_subdomains', []))}",
            f"Live hosts: {len(self._state.get('live_hosts', []))}",
            f"Endpoints: {len(self._state.get('endpoints', []))}",
            f"Parameters: {len(self._state.get('parameters', []))}",
            "",
            "-" * 70,
            "FINDINGS SUMMARY",
            "-" * 70,
            f"Confirmed vulnerabilities: {len(confirmed)}",
            f"Potential vulnerabilities: {len(potential)}",
            "",
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"  {sev}: {count}")

        lines.extend(["", "-" * 70, "CONFIRMED FINDINGS (sorted by severity)", "-" * 70, ""])

        sorted_confirmed = sorted(
            confirmed,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4),
        )

        for i, finding in enumerate(sorted_confirmed, 1):
            lines.extend([
                f"[{i}] {finding.get('type', 'Unknown').upper()} — {finding.get('severity', 'info').upper()}",
                f"    URL: {finding.get('url', 'N/A')}",
                f"    Description: {finding.get('description', 'N/A')}",
                f"    Reproduction: {finding.get('reproduction_steps', 'N/A')}",
                f"    Impact: {finding.get('impact', 'N/A')}",
                f"    Mitigation: {finding.get('mitigation', 'N/A')}",
                f"    Evidence: {finding.get('evidence_file', 'N/A')}",
                "",
            ])

        if potential:
            lines.extend(["-" * 70, "POTENTIAL FINDINGS (require manual verification)", "-" * 70, ""])
            for i, finding in enumerate(potential, 1):
                lines.extend([
                    f"[{i}] {finding.get('type', 'Unknown').upper()} — {finding.get('severity', 'info').upper()}",
                    f"    URL: {finding.get('url', 'N/A')}",
                    f"    Description: {finding.get('description', 'N/A')}",
                    f"    Evidence: {finding.get('evidence_file', 'N/A')}",
                    "",
                ])

        lines.extend(["=" * 70, "END OF REPORT", "=" * 70])

        path = os.path.join(self._dir, "executive_summary.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    def generate_all(self):
        self.generate_attack_surface()
        self.generate_potential_findings()
        self.generate_confirmed_findings()
        self.generate_evidence_index()
        self.generate_executive_summary()
```

**Step 4: Run tests**

```bash
pytest tests/test_reporting.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/reporting.py tests/test_reporting.py
git commit -m "feat: implement ReportGenerator with JSON reports and executive summary"
```

---

## Task 23: Wire Everything Together in Main

**Files:**
- Modify: `wstg_orchestrator/main.py`

**Step 1: Update main.py to register all modules and trigger reports**

Add module imports and registration in the `main()` function. Add report generation after scan completion in `Orchestrator.run()`.

**Step 2: Run full test suite**

```bash
pytest tests/ -v
```

Expected: All PASS

**Step 3: Commit**

```bash
git add wstg_orchestrator/main.py
git commit -m "feat: wire all modules and reporting into orchestrator"
```

---

## Execution Summary

| Task | Component | Dependencies |
|------|-----------|-------------|
| 1 | Project scaffold | None |
| 2 | StateManager | Task 1 |
| 3 | ConfigLoader + ScopeChecker | Task 1 |
| 4 | RateLimiter | Task 1 |
| 5 | CommandRunner | Task 1 |
| 6 | EvidenceLogger | Task 1 |
| 7 | HttpClient | Tasks 3, 4 |
| 8 | ParserUtils | Task 1 |
| 9 | CallbackServer | Task 1 |
| 10 | ScopeBuilder | Task 3 |
| 11 | BaseModule | Tasks 2, 3, 4, 6, 9 |
| 12 | Orchestrator | Tasks 2-11 |
| 13 | ReconModule | Tasks 5, 7, 8, 11 |
| 14-21 | Remaining modules | Task 11, 13 |
| 22 | ReportGenerator | Task 2 |
| 23 | Final wiring | All |
