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
