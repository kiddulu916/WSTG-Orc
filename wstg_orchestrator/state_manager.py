import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class StateManager:
    """Thread-safe state manager for WSTG scan orchestration with persistence."""

    def __init__(self, state_file: str, target_domain: str = "", company_name: str = ""):
        """
        Initialize StateManager.

        Args:
            state_file: Path to state JSON file
            target_domain: Target domain (only for fresh state)
            company_name: Company name (only for fresh state)
        """
        self.state_file = Path(state_file)
        self.lock = threading.Lock()

        # Try to load existing state
        if self.state_file.exists():
            self._load()
        else:
            # Create fresh state
            self.state = self._create_fresh_state(target_domain, company_name)
            self.save()

    def _create_fresh_state(self, target_domain: str, company_name: str) -> Dict[str, Any]:
        """Create a fresh state dictionary."""
        return {
            "target_domain": target_domain,
            "company_name": company_name,
            "scan_id": str(uuid.uuid4()),
            "scan_start": datetime.now(timezone.utc).isoformat(),
            "completed_phases": {},
            # List fields
            "discovered_subdomains": [],
            "live_hosts": [],
            "open_ports": [],
            "technologies": [],
            "server_versions": [],
            "frameworks": [],
            "endpoints": [],
            "parameters": [],
            "forms": [],
            "auth_endpoints": [],
            "api_endpoints": [],
            "cloud_assets": [],
            "potential_idor_candidates": [],
            "valid_usernames": [],
            "inferred_cves": [],
            "exposed_admin_paths": [],
            "pending_callbacks": [],
            "potential_vulnerabilities": [],
            "confirmed_vulnerabilities": [],
            "evidence_index": [],
        }

    def _load(self):
        """Load state from disk."""
        with open(self.state_file, 'r') as f:
            self.state = json.load(f)

    def get(self, key: str) -> Any:
        """
        Get a value from state under lock.

        Args:
            key: State key to retrieve

        Returns:
            Value associated with key
        """
        with self.lock:
            return self.state.get(key)

    def set(self, key: str, value: Any):
        """
        Set a value in state under lock.

        Args:
            key: State key to set
            value: Value to set
        """
        with self.lock:
            self.state[key] = value

    def enrich(self, key: str, values: List[Any]):
        """
        Append values to a list with deduplication under lock.

        Args:
            key: State key (must be a list)
            values: Values to append
        """
        with self.lock:
            if key not in self.state:
                self.state[key] = []

            current = self.state[key]
            if not isinstance(current, list):
                raise ValueError(f"Key '{key}' is not a list")

            # Add values with deduplication
            for value in values:
                if value not in current:
                    current.append(value)

    def save(self):
        """Write state to disk as JSON."""
        with self.lock:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)

    def mark_subcategory_complete(self, phase: str, subcategory: str):
        """
        Mark a subcategory as complete and save.

        Args:
            phase: Phase name
            subcategory: Subcategory name
        """
        with self.lock:
            if phase not in self.state["completed_phases"]:
                self.state["completed_phases"][phase] = {}

            self.state["completed_phases"][phase][subcategory] = True

        # Save automatically
        self.save()

    def mark_phase_complete(self, phase: str):
        """
        Mark a phase as complete and save.

        Args:
            phase: Phase name
        """
        with self.lock:
            if phase not in self.state["completed_phases"]:
                self.state["completed_phases"][phase] = {}

            self.state["completed_phases"][phase]["completed"] = True

        # Save automatically
        self.save()

    def is_phase_complete(self, phase: str) -> bool:
        """
        Check if a phase is marked complete.

        Args:
            phase: Phase name

        Returns:
            True if phase is complete
        """
        with self.lock:
            if phase not in self.state["completed_phases"]:
                return False
            return self.state["completed_phases"][phase].get("completed", False)

    def is_subcategory_complete(self, phase: str, subcategory: str) -> bool:
        """
        Check if a subcategory is marked complete.

        Args:
            phase: Phase name
            subcategory: Subcategory name

        Returns:
            True if subcategory is complete
        """
        with self.lock:
            if phase not in self.state["completed_phases"]:
                return False
            return self.state["completed_phases"][phase].get(subcategory, False)
