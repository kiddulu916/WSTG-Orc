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