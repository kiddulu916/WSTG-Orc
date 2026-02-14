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