# main.py
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
        self._modules.get(phase_name)

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

    from wstg_orchestrator.modules.reconnaissance import ReconModule
    from wstg_orchestrator.modules.fingerprinting import FingerprintingModule
    from wstg_orchestrator.modules.configuration_testing import ConfigTestingModule
    from wstg_orchestrator.modules.auth_testing import AuthTestingModule
    from wstg_orchestrator.modules.authorization_testing import AuthorizationTestingModule
    from wstg_orchestrator.modules.session_testing import SessionTestingModule
    from wstg_orchestrator.modules.input_validation import InputValidationModule
    from wstg_orchestrator.modules.business_logic import BusinessLogicModule
    from wstg_orchestrator.modules.api_testing import ApiTestingModule
    from wstg_orchestrator.reporting import ReportGenerator

    orch.register_module("reconnaissance", ReconModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("fingerprinting", FingerprintingModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("configuration_testing", ConfigTestingModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("auth_testing", AuthTestingModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("authorization_testing", AuthorizationTestingModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("session_testing", SessionTestingModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("input_validation", InputValidationModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("business_logic", BusinessLogicModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))
    orch.register_module("api_testing", ApiTestingModule(orch.state, orch.config, orch.scope_checker, orch.rate_limiter, orch.evidence_logger, orch.callback_server))

    asyncio.run(orch.run())

    # Generate reports after scan completion
    logger.info("Generating reports...")
    report_gen = ReportGenerator(orch.state._state, orch.evidence_logger.get_reports_dir())
    report_gen.generate_all()
    logger.info("Reports generated successfully.")


if __name__ == "__main__":
    main()