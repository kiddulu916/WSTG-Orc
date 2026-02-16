# Subdomain Enumeration Expansion — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand `passive_osint` to run 6 subdomain tools in parallel (subfinder, assetfinder, crt.sh, amass, github-subdomains, gitlab-subdomains) followed by altdns permutation + puredns resolution.

**Architecture:** Two-phase approach — Phase 1 runs all discovery tools concurrently via `asyncio.gather`, merges/dedupes/scope-filters results. Phase 2 feeds those into altdns for permutations, then puredns for resolution. Token-based tools (github/gitlab) resolve tokens from config YAML → env var → interactive prompt with config persistence.

**Tech Stack:** Python asyncio, subprocess, CommandRunner, ConfigLoader, YAML persistence

---

### Task 1: Add `run_pipeline` to CommandRunner

**Files:**
- Modify: `wstg_orchestrator/utils/command_runner.py:39` (after existing `run` method)
- Test: `tests/test_command_runner.py`

**Step 1: Write the failing test**

Add to `tests/test_command_runner.py`:

```python
def test_run_pipeline_success(runner):
    result = runner.run_pipeline("echo test", "echo hello | tr 'h' 'H'", timeout=5)
    assert result.returncode == 0
    assert "Hello" in result.stdout


def test_run_pipeline_timeout(runner):
    result = runner.run_pipeline("slow pipe", "sleep 10 | cat", timeout=1)
    assert result.timed_out is True


def test_run_pipeline_failure(runner):
    result = runner.run_pipeline("bad cmd", "nonexistent_cmd_xyz | cat", timeout=5)
    assert result.returncode != 0
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_command_runner.py::test_run_pipeline_success -v`
Expected: FAIL with "AttributeError: 'CommandRunner' object has no attribute 'run_pipeline'"

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/command_runner.py` after the `run` method (after line 82):

```python
def run_pipeline(
    self,
    description: str,
    command: str,
    timeout: int = 120,
    cwd: str | None = None,
) -> CommandResult:
    """Run a shell pipeline command (e.g. 'curl ... | jq ...')."""
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return CommandResult(
            tool=description, args=[command],
            returncode=proc.returncode,
            stdout=proc.stdout, stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"Pipeline timed out after {timeout}s: {description}")
        return CommandResult(
            tool=description, args=[command],
            returncode=-1, timed_out=True,
            stderr=f"Timed out after {timeout}s",
        )
    except Exception as e:
        logger.error(f"Error running pipeline {description}: {e}")
        return CommandResult(
            tool=description, args=[command],
            returncode=-1, stderr=str(e),
        )
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_command_runner.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/command_runner.py tests/test_command_runner.py
git commit -m "feat: add run_pipeline method to CommandRunner for shell pipelines"
```

---

### Task 2: Add `update_tool_config` to ConfigLoader

**Files:**
- Modify: `wstg_orchestrator/utils/config_loader.py:85` (after `get_tool_config`)
- Test: `tests/test_config_loader.py` (new — or add to existing if present)

**Step 1: Write the failing test**

Create/add to test file:

```python
import os
import tempfile
import pytest
import yaml
from wstg_orchestrator.utils.config_loader import ConfigLoader


@pytest.fixture
def config_file(tmp_path):
    config = {
        "program_scope": {"base_domain": "example.com"},
        "tool_configs": {"subfinder": {"extra_args": ["-all"]}},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))
    return str(path)


def test_update_tool_config_adds_new_key(config_file):
    loader = ConfigLoader(config_file)
    loader.update_tool_config("github_subdomains", "token", "ghp_abc123")

    # Verify in-memory
    assert loader.get_tool_config("github_subdomains")["token"] == "ghp_abc123"

    # Verify on disk
    with open(config_file) as f:
        raw = yaml.safe_load(f)
    assert raw["tool_configs"]["github_subdomains"]["token"] == "ghp_abc123"


def test_update_tool_config_preserves_existing(config_file):
    loader = ConfigLoader(config_file)
    loader.update_tool_config("github_subdomains", "token", "ghp_abc123")

    # subfinder config should still be there
    assert loader.get_tool_config("subfinder")["extra_args"] == ["-all"]


def test_update_tool_config_creates_tool_configs_section(tmp_path):
    config = {"program_scope": {"base_domain": "example.com"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(config))

    loader = ConfigLoader(str(path))
    loader.update_tool_config("gitlab_subdomains", "token", "glpat_xyz")
    assert loader.get_tool_config("gitlab_subdomains")["token"] == "glpat_xyz"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_config_loader.py::test_update_tool_config_adds_new_key -v`
Expected: FAIL with "AttributeError: 'ConfigLoader' object has no attribute 'update_tool_config'"

**Step 3: Write minimal implementation**

Add to `wstg_orchestrator/utils/config_loader.py` after `get_tool_config` (after line 86):

```python
def update_tool_config(self, tool_name: str, key: str, value):
    """Update a single key in a tool's config, persisting to YAML on disk."""
    if tool_name not in self._tools:
        self._tools[tool_name] = {}
    self._tools[tool_name][key] = value
    self._raw.setdefault("tool_configs", {})[tool_name] = self._tools[tool_name]
    self.save(self.config_path)
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_config_loader.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/utils/config_loader.py tests/test_config_loader.py
git commit -m "feat: add update_tool_config to ConfigLoader for token persistence"
```

---

### Task 3: Bundle default data files

**Files:**
- Create: `data/altdns-words.txt`
- Create: `data/resolvers.txt`

**Step 1: Create `data/altdns-words.txt`**

Standard altdns permutation wordlist (common prefixes/suffixes):

```
dev
staging
stage
stg
prod
production
test
testing
uat
qa
sandbox
demo
beta
alpha
internal
admin
api
app
web
portal
cdn
mail
email
ftp
vpn
ssh
ns
dns
mx
sql
db
database
cache
redis
elastic
search
monitor
grafana
kibana
jenkins
ci
cd
deploy
build
release
git
svn
repo
docker
k8s
kube
aws
gcp
azure
cloud
backup
bak
old
new
temp
tmp
```

**Step 2: Create `data/resolvers.txt`**

Standard public DNS resolvers:

```
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
```

**Step 3: Verify files exist**

Run: `ls -la data/altdns-words.txt data/resolvers.txt`
Expected: Both files present

**Step 4: Commit**

```bash
git add data/altdns-words.txt data/resolvers.txt
git commit -m "feat: bundle default altdns wordlist and DNS resolvers"
```

---

### Task 4: Add `_resolve_tool_token` helper and update TOOL_INSTALL_COMMANDS

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py:31-43`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

Add to `tests/test_reconnaissance.py`:

```python
import os

@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="ghp_test123")
def test_resolve_tool_token_from_prompt(mock_input, recon_module):
    """When no config or env token, prompts user and returns entered token."""
    recon_module.config.get_tool_config.return_value = {}
    with patch.dict(os.environ, {}, clear=True):
        token = recon_module._resolve_tool_token("github_subdomains", "GITHUB_TOKEN")
    assert token == "ghp_test123"


@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="")
def test_resolve_tool_token_blank_skips(mock_input, recon_module):
    """When user enters blank, returns None."""
    recon_module.config.get_tool_config.return_value = {}
    with patch.dict(os.environ, {}, clear=True):
        token = recon_module._resolve_tool_token("github_subdomains", "GITHUB_TOKEN")
    assert token is None


def test_resolve_tool_token_from_config(recon_module):
    """Token from config YAML is preferred."""
    recon_module.config.get_tool_config.return_value = {"token": "config_token"}
    token = recon_module._resolve_tool_token("github_subdomains", "GITHUB_TOKEN")
    assert token == "config_token"


def test_resolve_tool_token_from_env(recon_module):
    """Falls back to env var when config has no token."""
    recon_module.config.get_tool_config.return_value = {}
    with patch.dict(os.environ, {"GITHUB_TOKEN": "env_token"}):
        token = recon_module._resolve_tool_token("github_subdomains", "GITHUB_TOKEN")
    assert token == "env_token"


@patch("wstg_orchestrator.modules.reconnaissance.cli_input", return_value="new_token")
def test_resolve_tool_token_saves_to_config(mock_input, recon_module):
    """When user enters a token interactively, it's saved to config."""
    recon_module.config.get_tool_config.return_value = {}
    recon_module.config.update_tool_config = MagicMock()
    with patch.dict(os.environ, {}, clear=True):
        token = recon_module._resolve_tool_token("github_subdomains", "GITHUB_TOKEN")
    recon_module.config.update_tool_config.assert_called_once_with("github_subdomains", "token", "new_token")
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_reconnaissance.py::test_resolve_tool_token_from_config -v`
Expected: FAIL with "AttributeError"

**Step 3: Write implementation**

In `wstg_orchestrator/modules/reconnaissance.py`:

Update `TOOL_INSTALL_COMMANDS` (line 31):

```python
TOOL_INSTALL_COMMANDS = {
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    "whois": "apt install whois",
    "assetfinder": "go install -v github.com/tomnomnom/assetfinder@latest",
    "github-subdomains": "go install -v github.com/gwen001/github-subdomains@latest",
    "gitlab-subdomains": "go install -v github.com/gwen001/gitlab-subdomains@latest",
    "altdns": "pip install py-altdns",
    "puredns": "go install -v github.com/d3mondev/puredns/v2@latest",
    "curl": "apt install curl",
    "jq": "apt install jq",
}
```

Update `__init__` tool_configs list (line 41) to include new tools:

```python
self._cmd = CommandRunner(
    tool_configs={
        name: self.config.get_tool_config(name)
        for name in [
            "subfinder", "amass", "gau", "httpx", "whois",
            "assetfinder", "github_subdomains", "gitlab_subdomains",
            "altdns", "puredns",
        ]
    }
)
```

Add `_resolve_tool_token` method (after `_prompt_install_tool`, after line 131):

```python
def _resolve_tool_token(self, tool_config_name: str, env_var: str) -> str | None:
    """Resolve an API token from config -> env -> interactive prompt.

    Returns the token string, or None if unavailable/skipped.
    """
    # 1. Check config YAML
    cfg = self.config.get_tool_config(tool_config_name)
    token = cfg.get("token")
    if token:
        return token

    # 2. Check environment variable
    import os
    token = os.environ.get(env_var)
    if token:
        return token

    # 3. Interactive prompt
    self.logger.warning(f"No {env_var} found in config or environment.")
    token = cli_input(f"Enter {env_var} (blank to skip {tool_config_name}): ").strip()
    if not token:
        self.logger.info(f"No token provided, skipping {tool_config_name}")
        return None

    # Save to config for future runs
    self.config.update_tool_config(tool_config_name, "token", token)
    self.logger.info(f"Token saved to config for {tool_config_name}")
    return token
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_reconnaissance.py -k "resolve_tool_token" -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add token resolution helper and expand TOOL_INSTALL_COMMANDS"
```

---

### Task 5: Implement `_run_assetfinder`

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py` (add new method after `_run_amass`)
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_run_assetfinder_success(recon_module):
    mock_result = MagicMock(tool_missing=False, returncode=0,
                            stdout="sub1.example.com\nsub2.example.com\n")
    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        results = await recon_module._run_assetfinder("example.com")
    assert results == ["sub1.example.com", "sub2.example.com"]


@pytest.mark.asyncio
async def test_run_assetfinder_missing_prompts_install(recon_module):
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    success = MagicMock(tool_missing=False, returncode=0, stdout="sub.example.com\n", stderr="")
    with patch.object(recon_module._cmd, 'run', side_effect=[missing, success]):
        with patch.object(recon_module, '_prompt_install_tool', return_value=True):
            results = await recon_module._run_assetfinder("example.com")
    assert results == ["sub.example.com"]


@pytest.mark.asyncio
async def test_run_assetfinder_missing_declined(recon_module):
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    with patch.object(recon_module._cmd, 'run', return_value=missing):
        with patch.object(recon_module, '_prompt_install_tool', return_value=False):
            results = await recon_module._run_assetfinder("example.com")
    assert results == []
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_reconnaissance.py::test_run_assetfinder_success -v`
Expected: FAIL

**Step 3: Write implementation**

Add after `_run_amass` method (after line 319):

```python
async def _run_assetfinder(self, domain: str) -> list[str]:
    self.logger.info(f"Running assetfinder for domain: {domain}")
    result = self._cmd.run("assetfinder", ["--subs-only", domain], timeout=120)
    if result.tool_missing:
        if self._prompt_install_tool("assetfinder", self.TOOL_INSTALL_COMMANDS["assetfinder"]):
            result = self._cmd.run("assetfinder", ["--subs-only", domain], timeout=120)
        else:
            return []
    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "assetfinder", result.stdout)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return []
```

**Step 4: Run to verify pass**

Run: `pytest tests/test_reconnaissance.py -k "assetfinder" -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add _run_assetfinder subdomain tool"
```

---

### Task 6: Implement `_run_crtsh`

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_run_crtsh_success(recon_module):
    mock_result = MagicMock(returncode=0,
                            stdout="sub1.example.com\n*.example.com\nsub2.example.com\n",
                            timed_out=False)
    with patch.object(recon_module._cmd, 'run_pipeline', return_value=mock_result):
        results = await recon_module._run_crtsh("example.com")
    # Wildcards should be stripped
    assert "sub1.example.com" in results
    assert "sub2.example.com" in results
    assert "*.example.com" not in results


@pytest.mark.asyncio
async def test_run_crtsh_curl_missing(recon_module):
    """When curl is missing, prompts install. If declined, returns empty."""
    with patch.object(recon_module._cmd, 'is_tool_available', return_value=False):
        with patch.object(recon_module, '_prompt_install_tool', return_value=False):
            results = await recon_module._run_crtsh("example.com")
    assert results == []


@pytest.mark.asyncio
async def test_run_crtsh_failure(recon_module):
    mock_result = MagicMock(returncode=1, stdout="", timed_out=False)
    with patch.object(recon_module._cmd, 'is_tool_available', return_value=True):
        with patch.object(recon_module._cmd, 'run_pipeline', return_value=mock_result):
            results = await recon_module._run_crtsh("example.com")
    assert results == []
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_reconnaissance.py::test_run_crtsh_success -v`
Expected: FAIL

**Step 3: Write implementation**

```python
async def _run_crtsh(self, domain: str) -> list[str]:
    self.logger.info(f"Running crt.sh lookup for domain: {domain}")
    # Check curl and jq availability
    for tool in ("curl", "jq"):
        if not self._cmd.is_tool_available(tool):
            if not self._prompt_install_tool(tool, self.TOOL_INSTALL_COMMANDS[tool]):
                return []

    command = f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value'"
    result = self._cmd.run_pipeline("crt.sh", command, timeout=120)
    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "crtsh", result.stdout)
        subs = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("*"):
                subs.append(line)
        return subs
    self.logger.warning(f"crt.sh lookup failed for {domain}")
    return []
```

**Step 4: Run to verify pass**

Run: `pytest tests/test_reconnaissance.py -k "crtsh" -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add _run_crtsh subdomain tool via curl|jq pipeline"
```

---

### Task 7: Implement `_run_github_subdomains`

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_run_github_subdomains_success(recon_module):
    mock_result = MagicMock(tool_missing=False, returncode=0,
                            stdout="api.example.com\ndev.example.com\n")
    with patch.object(recon_module, '_resolve_tool_token', return_value="ghp_test"):
        with patch.object(recon_module._cmd, 'run', return_value=mock_result):
            results = await recon_module._run_github_subdomains("example.com")
    assert results == ["api.example.com", "dev.example.com"]


@pytest.mark.asyncio
async def test_run_github_subdomains_no_token(recon_module):
    """Skips when no token is available."""
    with patch.object(recon_module, '_resolve_tool_token', return_value=None):
        results = await recon_module._run_github_subdomains("example.com")
    assert results == []


@pytest.mark.asyncio
async def test_run_github_subdomains_missing_prompts_install(recon_module):
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    with patch.object(recon_module, '_resolve_tool_token', return_value="ghp_test"):
        with patch.object(recon_module._cmd, 'run', return_value=missing):
            with patch.object(recon_module, '_prompt_install_tool', return_value=False):
                results = await recon_module._run_github_subdomains("example.com")
    assert results == []
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_reconnaissance.py::test_run_github_subdomains_success -v`
Expected: FAIL

**Step 3: Write implementation**

```python
async def _run_github_subdomains(self, domain: str) -> list[str]:
    token = self._resolve_tool_token("github_subdomains", "GITHUB_TOKEN")
    if not token:
        return []

    self.logger.info(f"Running github-subdomains for domain: {domain}")
    result = self._cmd.run(
        "github-subdomains", ["-d", domain, "-t", token], timeout=120,
    )
    if result.tool_missing:
        if self._prompt_install_tool("github-subdomains", self.TOOL_INSTALL_COMMANDS["github-subdomains"]):
            result = self._cmd.run("github-subdomains", ["-d", domain, "-t", token], timeout=120)
        else:
            return []
    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "github_subdomains", result.stdout)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return []
```

**Step 4: Run to verify pass**

Run: `pytest tests/test_reconnaissance.py -k "github_subdomains" -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add _run_github_subdomains with token resolution"
```

---

### Task 8: Implement `_run_gitlab_subdomains`

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_run_gitlab_subdomains_success(recon_module):
    mock_result = MagicMock(tool_missing=False, returncode=0,
                            stdout="git.example.com\nci.example.com\n")
    with patch.object(recon_module, '_resolve_tool_token', return_value="glpat_test"):
        with patch.object(recon_module._cmd, 'run', return_value=mock_result):
            results = await recon_module._run_gitlab_subdomains("example.com")
    assert results == ["git.example.com", "ci.example.com"]


@pytest.mark.asyncio
async def test_run_gitlab_subdomains_no_token(recon_module):
    with patch.object(recon_module, '_resolve_tool_token', return_value=None):
        results = await recon_module._run_gitlab_subdomains("example.com")
    assert results == []
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_reconnaissance.py::test_run_gitlab_subdomains_success -v`
Expected: FAIL

**Step 3: Write implementation**

```python
async def _run_gitlab_subdomains(self, domain: str) -> list[str]:
    token = self._resolve_tool_token("gitlab_subdomains", "GITLAB_TOKEN")
    if not token:
        return []

    self.logger.info(f"Running gitlab-subdomains for domain: {domain}")
    result = self._cmd.run(
        "gitlab-subdomains", ["-d", domain, "-t", token], timeout=120,
    )
    if result.tool_missing:
        if self._prompt_install_tool("gitlab-subdomains", self.TOOL_INSTALL_COMMANDS["gitlab-subdomains"]):
            result = self._cmd.run("gitlab-subdomains", ["-d", domain, "-t", token], timeout=120)
        else:
            return []
    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "gitlab_subdomains", result.stdout)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return []
```

**Step 4: Run to verify pass**

Run: `pytest tests/test_reconnaissance.py -k "gitlab_subdomains" -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add _run_gitlab_subdomains with token resolution"
```

---

### Task 9: Implement `_run_altdns` and `_run_puredns`

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_run_altdns_success(recon_module):
    """altdns generates permutations and returns them as a list."""
    mock_result = MagicMock(tool_missing=False, returncode=0, stdout="", stderr="")
    permutation_content = "dev.sub.example.com\nstaging.sub.example.com\n"

    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        with patch("builtins.open", side_effect=[
            # First open: write input file (context manager)
            MagicMock(__enter__=MagicMock(), __exit__=MagicMock()),
            # Second open: read output file
            MagicMock(__enter__=MagicMock(return_value=MagicMock(
                read=MagicMock(return_value=permutation_content)
            )), __exit__=MagicMock()),
        ]):
            with patch("tempfile.mkstemp", side_effect=[
                (99, "/tmp/altdns_in.txt"),
                (100, "/tmp/altdns_out.txt"),
            ]):
                with patch("os.fdopen", return_value=MagicMock(__enter__=MagicMock(), __exit__=MagicMock())):
                    with patch("os.unlink"):
                        results = await recon_module._run_altdns(["sub.example.com"])
    assert "dev.sub.example.com" in results
    assert "staging.sub.example.com" in results


@pytest.mark.asyncio
async def test_run_altdns_missing_prompts_install(recon_module):
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    with patch.object(recon_module._cmd, 'run', return_value=missing):
        with patch.object(recon_module, '_prompt_install_tool', return_value=False):
            with patch("tempfile.mkstemp", return_value=(99, "/tmp/in.txt")):
                with patch("os.fdopen", return_value=MagicMock(__enter__=MagicMock(), __exit__=MagicMock())):
                    with patch("os.unlink"):
                        results = await recon_module._run_altdns(["sub.example.com"])
    assert results == []


@pytest.mark.asyncio
async def test_run_altdns_empty_input(recon_module):
    """altdns with no subdomains returns empty."""
    results = await recon_module._run_altdns([])
    assert results == []


@pytest.mark.asyncio
async def test_run_puredns_success(recon_module):
    mock_result = MagicMock(tool_missing=False, returncode=0,
                            stdout="dev.sub.example.com\n")
    with patch.object(recon_module._cmd, 'run', return_value=mock_result):
        with patch("tempfile.mkstemp", return_value=(99, "/tmp/puredns_in.txt")):
            with patch("os.fdopen", return_value=MagicMock(__enter__=MagicMock(), __exit__=MagicMock())):
                with patch("os.unlink"):
                    results = await recon_module._run_puredns(["dev.sub.example.com", "staging.sub.example.com"])
    assert results == ["dev.sub.example.com"]


@pytest.mark.asyncio
async def test_run_puredns_missing_prompts_install(recon_module):
    missing = MagicMock(tool_missing=True, returncode=1, stdout="", stderr="")
    with patch.object(recon_module._cmd, 'run', return_value=missing):
        with patch.object(recon_module, '_prompt_install_tool', return_value=False):
            with patch("tempfile.mkstemp", return_value=(99, "/tmp/in.txt")):
                with patch("os.fdopen", return_value=MagicMock(__enter__=MagicMock(), __exit__=MagicMock())):
                    with patch("os.unlink"):
                        results = await recon_module._run_puredns(["sub.example.com"])
    assert results == []
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_reconnaissance.py::test_run_altdns_empty_input -v`
Expected: FAIL

**Step 3: Write implementation**

```python
def _get_data_file(self, filename: str) -> str:
    """Return path to a bundled data file."""
    import os
    return os.path.join(os.path.dirname(__file__), "..", "..", "data", filename)

async def _run_altdns(self, subdomains: list[str]) -> list[str]:
    if not subdomains:
        return []

    import tempfile, os
    self.logger.info(f"Running altdns permutations on {len(subdomains)} subdomains")

    # Write input file
    fd_in, input_file = tempfile.mkstemp(suffix="_altdns_in.txt")
    with os.fdopen(fd_in, "w") as f:
        f.write("\n".join(subdomains))

    # Output file
    fd_out, output_file = tempfile.mkstemp(suffix="_altdns_out.txt")
    os.close(fd_out)

    # Resolve wordlist
    cfg = self.config.get_tool_config("altdns")
    wordlist = cfg.get("wordlist", self._get_data_file("altdns-words.txt"))

    result = self._cmd.run(
        "altdns", ["-i", input_file, "-o", output_file, "-w", wordlist],
        timeout=300,
    )
    if result.tool_missing:
        if self._prompt_install_tool("altdns", self.TOOL_INSTALL_COMMANDS["altdns"]):
            result = self._cmd.run(
                "altdns", ["-i", input_file, "-o", output_file, "-w", wordlist],
                timeout=300,
            )
        else:
            os.unlink(input_file)
            os.unlink(output_file)
            return []

    os.unlink(input_file)

    if result.returncode == 0:
        with open(output_file) as f:
            permutations = [line.strip() for line in f.read().splitlines() if line.strip()]
        self.evidence.log_tool_output("reconnaissance", "altdns", "\n".join(permutations))
        os.unlink(output_file)
        self.logger.info(f"altdns generated {len(permutations)} permutations")
        return permutations

    os.unlink(output_file)
    return []

async def _run_puredns(self, subdomains: list[str]) -> list[str]:
    if not subdomains:
        return []

    import tempfile, os
    self.logger.info(f"Running puredns resolve on {len(subdomains)} subdomains")

    fd, input_file = tempfile.mkstemp(suffix="_puredns_in.txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(subdomains))

    cfg = self.config.get_tool_config("puredns")
    resolvers = cfg.get("resolvers", self._get_data_file("resolvers.txt"))

    result = self._cmd.run(
        "puredns", ["resolve", input_file, "--resolvers", resolvers],
        timeout=300,
    )
    if result.tool_missing:
        if self._prompt_install_tool("puredns", self.TOOL_INSTALL_COMMANDS["puredns"]):
            result = self._cmd.run(
                "puredns", ["resolve", input_file, "--resolvers", resolvers],
                timeout=300,
            )
        else:
            os.unlink(input_file)
            return []

    os.unlink(input_file)

    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "puredns", result.stdout)
        resolved = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        self.logger.info(f"puredns resolved {len(resolved)} subdomains")
        return resolved
    return []
```

**Step 4: Run to verify pass**

Run: `pytest tests/test_reconnaissance.py -k "altdns or puredns" -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: add _run_altdns and _run_puredns for permutation + resolution"
```

---

### Task 10: Refactor `_passive_osint` — parallel Phase 1 + sequential Phase 2

**Files:**
- Modify: `wstg_orchestrator/modules/reconnaissance.py:235-247`
- Test: `tests/test_reconnaissance.py`

**Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_passive_osint_runs_all_tools_parallel(recon_module):
    """All Phase 1 tools are called for each domain."""
    tool_calls = []

    async def mock_subfinder(domain=None):
        tool_calls.append(("subfinder", domain))
        return ["sub1.example.com"]

    async def mock_assetfinder(domain):
        tool_calls.append(("assetfinder", domain))
        return ["sub2.example.com"]

    async def mock_crtsh(domain):
        tool_calls.append(("crtsh", domain))
        return ["sub3.example.com"]

    async def mock_amass(domain=None):
        tool_calls.append(("amass", domain))
        return ["sub4.example.com"]

    async def mock_github(domain):
        tool_calls.append(("github", domain))
        return ["sub5.example.com"]

    async def mock_gitlab(domain):
        tool_calls.append(("gitlab", domain))
        return ["sub6.example.com"]

    async def mock_altdns(subs):
        tool_calls.append(("altdns", len(subs)))
        return ["dev.sub1.example.com"]

    async def mock_puredns(subs):
        tool_calls.append(("puredns", len(subs)))
        return ["dev.sub1.example.com"]

    with patch.object(recon_module, '_run_subfinder', side_effect=mock_subfinder):
        with patch.object(recon_module, '_run_assetfinder', side_effect=mock_assetfinder):
            with patch.object(recon_module, '_run_crtsh', side_effect=mock_crtsh):
                with patch.object(recon_module, '_run_amass', side_effect=mock_amass):
                    with patch.object(recon_module, '_run_github_subdomains', side_effect=mock_github):
                        with patch.object(recon_module, '_run_gitlab_subdomains', side_effect=mock_gitlab):
                            with patch.object(recon_module, '_run_altdns', side_effect=mock_altdns):
                                with patch.object(recon_module, '_run_puredns', side_effect=mock_puredns):
                                    await recon_module._passive_osint()

    # All 6 discovery tools + altdns + puredns should have been called
    tool_names = [t[0] for t in tool_calls]
    assert "subfinder" in tool_names
    assert "assetfinder" in tool_names
    assert "crtsh" in tool_names
    assert "amass" in tool_names
    assert "github" in tool_names
    assert "gitlab" in tool_names
    assert "altdns" in tool_names
    assert "puredns" in tool_names


@pytest.mark.asyncio
async def test_passive_osint_deduplicates_results(recon_module):
    """Duplicate subdomains from multiple tools are deduplicated."""
    async def mock_subfinder(domain=None):
        return ["sub.example.com", "api.example.com"]

    async def mock_assetfinder(domain):
        return ["sub.example.com", "cdn.example.com"]

    async def noop(domain=None):
        return []

    async def noop_list(subs):
        return []

    with patch.object(recon_module, '_run_subfinder', side_effect=mock_subfinder):
        with patch.object(recon_module, '_run_assetfinder', side_effect=mock_assetfinder):
            with patch.object(recon_module, '_run_crtsh', side_effect=noop):
                with patch.object(recon_module, '_run_amass', side_effect=noop):
                    with patch.object(recon_module, '_run_github_subdomains', side_effect=noop):
                        with patch.object(recon_module, '_run_gitlab_subdomains', side_effect=noop):
                            with patch.object(recon_module, '_run_altdns', side_effect=noop_list):
                                with patch.object(recon_module, '_run_puredns', side_effect=noop_list):
                                    await recon_module._passive_osint()

    # Find the discovered_subdomains enrich call
    for call in recon_module.state.enrich.call_args_list:
        if call.args[0] == "discovered_subdomains":
            subs = call.args[1]
            # Should be deduplicated
            assert len(subs) == len(set(subs))
            assert "sub.example.com" in subs
            assert "api.example.com" in subs
            assert "cdn.example.com" in subs
            break


@pytest.mark.asyncio
async def test_passive_osint_skips_phase2_when_empty(recon_module):
    """altdns/puredns are not called when Phase 1 returns nothing."""
    async def noop(domain=None):
        return []

    altdns_called = False

    async def mock_altdns(subs):
        nonlocal altdns_called
        altdns_called = True
        return []

    # Make scope filter reject everything
    recon_module.scope.is_in_scope.return_value = False

    with patch.object(recon_module, '_run_subfinder', side_effect=noop):
        with patch.object(recon_module, '_run_assetfinder', side_effect=noop):
            with patch.object(recon_module, '_run_crtsh', side_effect=noop):
                with patch.object(recon_module, '_run_amass', side_effect=noop):
                    with patch.object(recon_module, '_run_github_subdomains', side_effect=noop):
                        with patch.object(recon_module, '_run_gitlab_subdomains', side_effect=noop):
                            with patch.object(recon_module, '_run_altdns', side_effect=mock_altdns):
                                with patch.object(recon_module, '_run_puredns', return_value=[]):
                                    await recon_module._passive_osint()

    assert not altdns_called


@pytest.mark.asyncio
async def test_passive_osint_phase2_adds_resolved_permutations(recon_module):
    """Resolved permutations from puredns are added to discovered_subdomains."""
    async def mock_subfinder(domain=None):
        return ["sub.example.com"]

    async def noop(domain=None):
        return []

    async def mock_altdns(subs):
        return ["dev.sub.example.com", "staging.sub.example.com"]

    async def mock_puredns(subs):
        return ["dev.sub.example.com"]  # only one resolves

    with patch.object(recon_module, '_run_subfinder', side_effect=mock_subfinder):
        with patch.object(recon_module, '_run_assetfinder', side_effect=noop):
            with patch.object(recon_module, '_run_crtsh', side_effect=noop):
                with patch.object(recon_module, '_run_amass', side_effect=noop):
                    with patch.object(recon_module, '_run_github_subdomains', side_effect=noop):
                        with patch.object(recon_module, '_run_gitlab_subdomains', side_effect=noop):
                            with patch.object(recon_module, '_run_altdns', side_effect=mock_altdns):
                                with patch.object(recon_module, '_run_puredns', side_effect=mock_puredns):
                                    await recon_module._passive_osint()

    # Collect all discovered_subdomains enrich calls
    all_subs = []
    for call in recon_module.state.enrich.call_args_list:
        if call.args[0] == "discovered_subdomains":
            all_subs.extend(call.args[1])
    assert "dev.sub.example.com" in all_subs
    assert "sub.example.com" in all_subs
```

**Step 2: Run to verify failure**

Run: `pytest tests/test_reconnaissance.py::test_passive_osint_runs_all_tools_parallel -v`
Expected: FAIL (current `_passive_osint` only calls subfinder)

**Step 3: Replace `_passive_osint` implementation**

Replace lines 235-247 in `reconnaissance.py`:

```python
async def _passive_osint(self):
    self.logger.info("Starting passive OSINT - subdomain enumeration")

    target_domains = self._get_target_domains()

    # Phase 1: Run all discovery tools in parallel per domain
    all_subdomains = []
    for domain in target_domains:
        results = await asyncio.gather(
            self._run_subfinder(domain),
            self._run_assetfinder(domain),
            self._run_crtsh(domain),
            self._run_amass(domain),
            self._run_github_subdomains(domain),
            self._run_gitlab_subdomains(domain),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, list):
                all_subdomains.extend(result)
            elif isinstance(result, Exception):
                self.logger.warning(f"Tool failed for {domain}: {result}")

    all_subdomains = list(set(self._filter_in_scope(all_subdomains)))
    self.state.enrich("discovered_subdomains", all_subdomains)
    self.evidence.log_parsed("reconnaissance", "subdomains", all_subdomains)
    self.logger.info(f"Phase 1: Found {len(all_subdomains)} unique subdomains")

    # Phase 2: Permutation + Resolution
    if not all_subdomains:
        self.logger.warning("No subdomains found, skipping permutation phase")
        return

    permutations = await self._run_altdns(all_subdomains)
    if permutations:
        resolved = await self._run_puredns(permutations)
        if resolved:
            resolved = list(set(self._filter_in_scope(resolved)))
            self.state.enrich("discovered_subdomains", resolved)
            self.evidence.log_parsed("reconnaissance", "permutation_subdomains", resolved)
            self.logger.info(f"Phase 2: Resolved {len(resolved)} permutation subdomains")
    else:
        self.logger.info("No permutations generated, skipping resolution")
```

**Step 4: Also refactor `_run_subfinder` to remove amass fallback**

Replace `_run_subfinder` (lines 293-305) — remove the amass fallback since amass is now standalone:

```python
async def _run_subfinder(self, domain: str | None = None) -> list[str]:
    target = domain or self.config.base_domain
    self.logger.info(f"Running subfinder for domain: {target}")
    result = self._cmd.run(
        "subfinder", ["-d", target, "-silent"], timeout=300,
    )
    if result.tool_missing:
        self.logger.warning("subfinder not found, skipping")
        return []
    if result.returncode == 0:
        self.evidence.log_tool_output("reconnaissance", "subfinder", result.stdout)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return []
```

**Step 5: Run ALL tests**

Run: `pytest tests/test_reconnaissance.py -v`
Expected: ALL PASS (some old tests may need updating — see step 6)

**Step 6: Update old test that relied on subfinder→amass fallback**

The existing `test_passive_osint_runs_subfinder` (line 40) needs updating since `_passive_osint` now calls all tools. Update it to mock all tools:

```python
@pytest.mark.asyncio
async def test_passive_osint_runs_subfinder(recon_module):
    async def noop(domain=None):
        return []

    async def noop_list(subs):
        return []

    with patch.object(recon_module, '_run_subfinder', new_callable=AsyncMock, return_value=["sub.example.com"]):
        with patch.object(recon_module, '_run_assetfinder', side_effect=noop):
            with patch.object(recon_module, '_run_crtsh', side_effect=noop):
                with patch.object(recon_module, '_run_amass', side_effect=noop):
                    with patch.object(recon_module, '_run_github_subdomains', side_effect=noop):
                        with patch.object(recon_module, '_run_gitlab_subdomains', side_effect=noop):
                            with patch.object(recon_module, '_run_altdns', side_effect=noop_list):
                                with patch.object(recon_module, '_run_puredns', return_value=[]):
                                    await recon_module._passive_osint()
        recon_module.state.enrich.assert_any_call("discovered_subdomains", ["sub.example.com"])
```

Similarly update `test_passive_osint_uses_enumeration_domains` (line 47).

**Step 7: Run full test suite**

Run: `pytest tests/ -v`
Expected: ALL PASS

**Step 8: Commit**

```bash
git add wstg_orchestrator/modules/reconnaissance.py tests/test_reconnaissance.py
git commit -m "feat: refactor passive_osint to parallel Phase 1 + altdns/puredns Phase 2"
```

---

### Task 11: Final verification

**Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: ALL PASS

**Step 2: Verify no import errors**

Run: `python -c "from wstg_orchestrator.modules.reconnaissance import ReconModule; print('OK')"`
Expected: "OK"

**Step 3: Verify data files exist**

Run: `ls -la data/altdns-words.txt data/resolvers.txt`
Expected: Both files present with content

**Step 4: Commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix: final cleanup for subdomain enumeration expansion"
```
