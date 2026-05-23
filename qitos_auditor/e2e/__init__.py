"""DeepAudit e2e test framework — model endpoints, targets, scoring, and runner."""

from .models import ModelEndpoint, MODEL_ENDPOINTS, build_llm_for_endpoint
from .targets import AuditTarget, TARGETS
from .target_manager import AuditTargetManager
from .criteria import TierCriterion, get_criteria, TIER_PASS_RATES
from .scorer import AuditorE2EScorer
from .runner import run_auditor_e2e_task, run_auditor_e2e_matrix

__all__ = [
    "ModelEndpoint", "MODEL_ENDPOINTS", "build_llm_for_endpoint",
    "AuditTarget", "TARGETS",
    "AuditTargetManager",
    "TierCriterion", "get_criteria", "TIER_PASS_RATES",
    "AuditorE2EScorer",
    "run_auditor_e2e_task", "run_auditor_e2e_matrix",
]
