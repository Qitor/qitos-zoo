"""Auditor e2e runner — orchestrates a single e2e test run.

Downloads targets, runs DeepAudit, scores results.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from .criteria import TIER_PASS_RATES, get_criteria
from .models import MODEL_ENDPOINTS, build_llm_for_endpoint
from .report import CriterionScore, ScoreReport
from .scorer import AuditorE2EScorer
from .target_manager import AuditTargetManager
from .targets import TARGETS

# Late import to avoid circular dependency
# from ..orchestrator.flow import AuditFlow  # imported inside run_auditor_e2e_task

logger = logging.getLogger(__name__)


def _default_task_description(tier: int, target_name: str) -> str:
    target = TARGETS.get(target_name)
    languages = ", ".join(target.languages) if target else "unknown"

    if tier == 1:
        return "Perform a quick security audit of this codebase"
    elif tier == 2:
        return (
            "Analyze the codebase structure and identify the technology stack, "
            "entry points, and security-relevant code patterns. "
            "Focus on understanding what the application does and where user input flows."
        )
    else:
        return (
            f"Perform a comprehensive security audit of this {languages} "
            "codebase. Identify all security vulnerabilities including injection flaws, "
            "authentication issues, access control problems, and cryptographic weaknesses. "
            "For each finding, provide the specific file, line number, and evidence."
        )


def run_auditor_e2e_task(
    *,
    target_name: str,
    tier: int,
    model_endpoint: str,
    task_description: str = "",
    config_overrides: Optional[Dict[str, Any]] = None,
    playground_root: str = "playground",
) -> ScoreReport:
    """Run a single DeepAudit e2e test and return a scored report.

    Parameters
    ----------
    target_name : str
        Name from TARGETS registry (e.g. "synthetic-flask").
    tier : int
        Test tier (1=smoke, 2=recon, 3=vuln_discovery).
    model_endpoint : str
        Name from MODEL_ENDPOINTS (e.g. "deepseek-v4-pro").
    task_description : str
        Audit task description. Auto-generated if empty.
    config_overrides : dict | None
        DeepAuditConfig field overrides.
    playground_root : str
        Root directory for cloned repos.
    """
    from qitos_zoo.qitos_auditor.config.defaults import DeepAuditConfig
    from qitos_zoo.qitos_auditor.runner import DeepAuditRunner

    target = TARGETS.get(target_name)
    if target is None:
        raise ValueError(f"Unknown target: {target_name}. Available: {list(TARGETS.keys())}")

    criteria = get_criteria(tier, target_name)
    if not criteria:
        return ScoreReport(tier=tier, target_name=target_name, scores=[])

    endpoint = MODEL_ENDPOINTS[model_endpoint]
    pass_rate_threshold = TIER_PASS_RATES.get(tier, 1.0)

    try:
        # Download/prepare target
        manager = AuditTargetManager(target, playground_root=playground_root)
        target_path = manager.prepare()
        ground_truth = manager.get_ground_truth()

        # Build task description
        if not task_description:
            task_description = _default_task_description(tier, target_name)

        # Build LLM
        llm = build_llm_for_endpoint(model_endpoint)

        # Build DeepAuditConfig with tier-based budgets
        tier_budgets = {
            1: {"max_steps_recon": 6, "max_steps_analysis": 6, "max_steps_verification": 5},
            2: {"max_steps_recon": 8, "max_steps_analysis": 10, "max_steps_verification": 8},
            3: {"max_steps_recon": 12, "max_steps_analysis": 20, "max_steps_verification": 15},
        }
        budget = tier_budgets.get(tier, tier_budgets[2])

        config_params: Dict[str, Any] = {
            "model_provider": "openai-compatible",
            "model_name": endpoint.model,
            "api_key": endpoint.api_key,
            "base_url": endpoint.base_url,
            "temperature": endpoint.temperature,
            "max_tokens": endpoint.max_tokens,
            "target_path": target_path,
            "fast_mode": tier <= 2,
            "enable_semgrep": tier >= 3,
            "enable_bandit": tier >= 3 and "python" in target.languages,
            "enable_gitleaks": tier >= 3,
            "enable_npm_audit": tier >= 3 and "javascript" in target.languages,
            "enable_osv_scanner": False,
            "sandbox_enabled": False,
            "knowledge_enabled": True,
            "report_format": "markdown",
            **budget,
        }
        if config_overrides:
            config_params.update(config_overrides)

        config = DeepAuditConfig(**config_params)

        # Run DeepAudit via AuditFlow
        from qitos_zoo.qitos_auditor.orchestrator.flow import AuditFlow

        started = time.time()
        flow = AuditFlow(config=config, llm=llm)
        result = flow.run(task_description, target_path=target_path)
        elapsed = time.time() - started

        logger.info(
            f"DeepAudit completed in {elapsed:.1f}s -- "
            f"status={result.status}, findings={len(result.findings)}"
        )

        # Score results
        scorer = AuditorE2EScorer()
        report = scorer.score(
            result, criteria, ground_truth,
            tier=tier, target_name=target_name,
        )
        return report

    except Exception as e:
        logger.error(f"DeepAudit e2e run failed: {e}")
        # Return a failed report
        fallback = [
            CriterionScore(
                name=c.name, passed=False, points=0.0,
                required=c.required, detail=f"Run error: {e}",
            )
            for c in criteria
        ] or [CriterionScore(
            name="run_error", passed=False, points=0.0,
            required=True, detail=str(e),
        )]
        return ScoreReport(tier=tier, target_name=target_name, scores=fallback)


def run_auditor_e2e_matrix(
    *,
    target_names: Optional[List[str]] = None,
    model_endpoints: Optional[List[str]] = None,
    tiers: Optional[List[int]] = None,
    playground_root: str = "playground",
) -> Dict[str, ScoreReport]:
    """Run a full cross-product matrix of targets x models x tiers.

    Returns a dict keyed by "{target}|{model}|{tier}".
    """
    target_names = target_names or list(TARGETS.keys())
    model_endpoints = model_endpoints or list(MODEL_ENDPOINTS.keys())
    tiers = tiers or [1, 2, 3]

    results: Dict[str, ScoreReport] = {}
    for target_name in target_names:
        target = TARGETS.get(target_name)
        if target is None:
            continue
        for model_endpoint in model_endpoints:
            for tier in tiers:
                if tier < target.min_tier or tier > target.max_tier:
                    continue
                key = f"{target_name}|{model_endpoint}|{tier}"
                logger.info(f"Running: {key}")
                results[key] = run_auditor_e2e_task(
                    target_name=target_name,
                    tier=tier,
                    model_endpoint=model_endpoint,
                    playground_root=playground_root,
                )
    return results
