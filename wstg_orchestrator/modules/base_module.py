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