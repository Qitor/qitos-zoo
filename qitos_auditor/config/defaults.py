"""DeepAudit configuration defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DeepAuditConfig:
    """Configuration for a DeepAudit security audit run.

    Attributes
    ----------
    model_provider : str
        LLM provider name (e.g. "openai-compatible").
    model_name : str
        LLM model name (e.g. "qwen-plus", "deepseek-chat").
    api_key : str | None
        API key for the LLM provider.
    base_url : str | None
        Custom API base URL.
    max_steps_orchestrator : int
        Maximum Engine steps for the Orchestrator agent.
    max_steps_recon : int
        Maximum Engine steps for the Recon agent.
    max_steps_analysis : int
        Maximum Engine steps for the Analysis agent.
    max_steps_verification : int
        Maximum Engine steps for the Verification agent.
    max_total_steps : int
        Maximum total Engine steps for the entire run.
    max_runtime_seconds : int
        Wall-clock timeout in seconds. 0 = no limit.
    target_path : str
        Path to the codebase to audit.
    workspace : str
        Local workspace directory for output files.
    enable_semgrep : bool
        Whether to enable Semgrep SAST scanning.
    enable_bandit : bool
        Whether to enable Bandit Python scanning.
    enable_gitleaks : bool
        Whether to enable Gitleaks secret detection.
    enable_npm_audit : bool
        Whether to enable npm audit for Node.js.
    enable_safety_check : bool
        Whether to enable safety/pip-audit for Python.
    enable_trufflehog : bool
        Whether to enable TruffleHog deep secret scanning.
    enable_osv_scanner : bool
        Whether to enable OSV-Scanner dependency scanning.
    enable_kunlun : bool
        Whether to enable Kunlun-M static analysis.
    external_timeout : int
        Timeout for external scanner commands in seconds.
    sandbox_enabled : bool
        Whether Docker sandbox is available for verification.
    sandbox_image : str
        Docker image for sandbox execution.
    knowledge_enabled : bool
        Whether to inject vulnerability/framework knowledge into prompts.
    report_format : str
        Output report format: "markdown", "json", or "sarif".
    max_findings : int
        Maximum number of findings to report.
    language : str
        Response language (e.g. "en", "zh").
    fast_mode : bool
        If True, reduce step budgets for faster (shallower) audits.
    temperature : float
        LLM temperature.
    max_tokens : int
        LLM max output tokens.
    context_window : int | None
        Total model context window in tokens. Auto-inferred if None.
    """

    # LLM settings
    model_provider: str = "openai-compatible"
    model_name: str = "qwen-plus"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.3
    max_tokens: int = 4096
    context_window: Optional[int] = None

    # Agent step budgets (maps to DeepAudit max iterations)
    max_steps_orchestrator: int = 20
    max_steps_recon: int = 15
    max_steps_analysis: int = 30
    max_steps_verification: int = 25

    # Global limits
    max_total_steps: int = 150
    max_runtime_seconds: int = 0  # 0 = no limit

    # Workspace
    workspace: str = "./workspace"
    target_path: str = "."

    # External scanner toggles
    enable_semgrep: bool = True
    enable_bandit: bool = True
    enable_gitleaks: bool = True
    enable_npm_audit: bool = True
    enable_safety_check: bool = True
    enable_trufflehog: bool = False
    enable_osv_scanner: bool = True
    enable_kunlun: bool = False
    external_timeout: int = 120

    # Knowledge system
    knowledge_enabled: bool = True

    # Sandbox settings
    sandbox_enabled: bool = True
    sandbox_image: str = "python:3.11-slim"

    # Report settings
    report_format: str = "markdown"  # markdown | json | sarif
    max_findings: int = 100

    # Resilience settings
    rate_limit_rpm: int = 60
    tool_timeout_seconds: Dict[str, int] = field(default_factory=dict)
    max_findings_per_agent: int = 100
    max_file_size_bytes: int = 10_000_000
    allowed_file_extensions: List[str] = field(default_factory=list)
    blocked_directories: List[str] = field(default_factory=lambda: [
        ".git", "__pycache__", "node_modules", ".venv", "venv", ".tox",
    ])

    # Language
    language: str = "en"

    # Fast mode
    fast_mode: bool = False

    def __post_init__(self):
        if self.fast_mode:
            self.max_steps_recon = 8
            self.max_steps_analysis = 15
            self.max_steps_verification = 12

    def validate_config(self) -> List[str]:
        """Validate config and return list of warning messages. Empty list = valid."""
        warnings = []
        if self.max_steps_recon < 3:
            warnings.append("max_steps_recon < 3 may produce incomplete recon")
        if self.max_steps_analysis < 5:
            warnings.append("max_steps_analysis < 5 may miss vulnerabilities")
        if self.max_steps_verification < 3:
            warnings.append("max_steps_verification < 3 may produce incomplete verification")
        if self.max_findings_per_agent < 1:
            warnings.append("max_findings_per_agent must be >= 1")
        if self.rate_limit_rpm < 1:
            warnings.append("rate_limit_rpm must be >= 1")
        if self.external_timeout < 10:
            warnings.append("external_timeout < 10 may cause scanner timeouts")
        if self.report_format not in ("markdown", "json", "sarif"):
            warnings.append(f"Unknown report_format '{self.report_format}', defaulting to markdown")
            self.report_format = "markdown"
        return warnings
