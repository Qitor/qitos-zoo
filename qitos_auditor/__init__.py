"""DeepAudit — Multi-Agent Code Security Audit System.

A QitOS-based implementation of the DeepAudit security audit platform,
featuring 4 specialist agents (Orchestrator, Recon, Analysis, Verification),
40+ security tools, and anti-hallucination safeguards.

SECURITY NOTICE: This module provides security testing tools intended for
authorized security auditing only. It is NOT exported from qitos by default.
Use `from qitos_zoo.qitos_auditor import ...` explicitly.

Usage:
    from qitos_zoo.qitos_auditor import DeepAuditRunner, DeepAuditConfig

    config = DeepAuditConfig(
        target_path="/path/to/codebase",
        api_key="your-llm-api-key",
    )
    runner = DeepAuditRunner(config)
    result = runner.run("Audit this codebase for vulnerabilities")
    print(result.report)
"""

from .config.defaults import DeepAuditConfig
from .runner import DeepAuditRunner
from .orchestrator.flow import AuditFlow, AuditResult
from .agents.orchestrator import OrchestratorAgent, HandoffPayload, FindingEntry
from .agents.recon import ReconAgent
from .agents.analysis import AnalysisAgent
from .agents.verification import VerificationAgent

__all__ = [
    "DeepAuditRunner",
    "DeepAuditConfig",
    "AuditFlow",
    "AuditResult",
    "OrchestratorAgent",
    "HandoffPayload",
    "FindingEntry",
    "ReconAgent",
    "AnalysisAgent",
    "VerificationAgent",
]
