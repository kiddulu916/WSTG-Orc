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
                ["bash", "-o", "pipefail", "-c", command],
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
