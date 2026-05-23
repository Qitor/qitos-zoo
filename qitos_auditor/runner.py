"""DeepAuditRunner — high-level entry point for running security audits."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .config.defaults import DeepAuditConfig
from .orchestrator.flow import AuditFlow, AuditResult


class DeepAuditRunner:
    """High-level entry point for running DeepAudit security audits.

    Usage:
        config = DeepAuditConfig(
            model_provider="openai-compatible",
            model_name="qwen-plus",
            api_key="your-key",
            target_path="/path/to/codebase",
        )
        runner = DeepAuditRunner(config)
        result = runner.run("Audit this codebase for security vulnerabilities")
        print(result.report)
    """

    def __init__(self, config: Optional[DeepAuditConfig] = None, llm: Any = None):
        self.config = config or DeepAuditConfig()
        self.llm = llm
        self._create_llm_if_needed()

    def _create_llm_if_needed(self) -> None:
        """Create LLM instance from config if not provided."""
        if self.llm is not None:
            return

        provider = self.config.model_provider
        if provider == "openai-compatible":
            try:
                from qitos.models import ModelFactory
                self.llm = ModelFactory.create(
                    "openai-compatible",
                    model=self.config.model_name,
                    api_key=self.config.api_key,
                    base_url=self.config.base_url,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                )
            except ImportError:
                pass

    def run(
        self,
        task: str = "Perform a comprehensive security audit of this codebase",
        target_path: Optional[str] = None,
        **kwargs: Any,
    ) -> AuditResult:
        """Execute a full security audit.

        Parameters
        ----------
        task : str
            Description of the audit task.
        target_path : str | None
            Path to the codebase. Falls back to config.target_path.
        **kwargs
            Additional overrides for DeepAuditConfig fields.

        Returns
        -------
        AuditResult
            The complete audit result with report, findings, and metadata.
        """
        # Apply any config overrides
        if kwargs:
            for key, value in kwargs.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        target = target_path or self.config.target_path

        flow = AuditFlow(config=self.config, llm=self.llm)
        return flow.run(task, target_path=target)
