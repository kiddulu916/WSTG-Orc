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