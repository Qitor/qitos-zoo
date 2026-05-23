"""Tier-based scoring criteria for DeepAudit e2e testing.

Tiers:
- Tier 1 (Smoke): Does the pipeline complete without crashing?
- Tier 2 (Reconnaissance): Does the agent identify tech stack and entry points?
- Tier 3 (Vulnerability Discovery): Does the agent find known vulnerabilities?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class TierCriterion:
    """One verifiable success condition for an audit test tier.

    check_type values:
    - "pipeline_completed": AuditFlow.run() completes
    - "report_produced": Report is non-empty
    - "tech_stack_identified": Correct language/framework detected
    - "vuln_found": Specific vulnerability type mentioned in findings
    - "vuln_in_file": Vulnerability found in the correct file
    - "vuln_with_evidence": Vulnerability has code evidence
    - "finding_count_min": Minimum number of findings produced
    - "report_contains": Report text matches a pattern
    """

    name: str
    description: str
    check_type: str
    check_params: Dict[str, Any] = field(default_factory=dict)
    points: float = 1.0
    required: bool = True


# ── Tier 1: Smoke (any target) ────────────────────────────────────

TIER1_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="pipeline_completed",
        description="AuditFlow.run() completes without error",
        check_type="pipeline_completed",
        required=True,
    ),
    TierCriterion(
        name="report_produced",
        description="Audit report is non-empty (>=300 chars)",
        check_type="report_produced",
        required=True,
    ),
    TierCriterion(
        name="findings_produced",
        description="At least 1 finding produced",
        check_type="finding_count_min",
        check_params={"min_count": 1},
        required=False,
    ),
]


# ── Tier 2: Reconnaissance ────────────────────────────────────────

TIER2_SYNTHETIC_FLASK_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="python_identified",
        description="Agent identifies Python as primary language",
        check_type="tech_stack_identified",
        check_params={"keywords": ["python", "flask"]},
        required=True,
    ),
    TierCriterion(
        name="flask_identified",
        description="Agent identifies Flask framework",
        check_type="tech_stack_identified",
        check_params={"keywords": ["flask"]},
        required=False,
    ),
    TierCriterion(
        name="routes_identified",
        description="Agent discovers web routes/endpoints",
        check_type="report_contains",
        check_params={"pattern": "route|endpoint|/login|/hello|/ping|/download"},
        required=False,
    ),
]

TIER2_DVWA_SRC_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="php_identified",
        description="Agent identifies PHP as primary language",
        check_type="tech_stack_identified",
        check_params={"keywords": ["php"]},
        required=True,
    ),
    TierCriterion(
        name="vulnerability_dirs_found",
        description="Agent discovers vulnerability directories",
        check_type="report_contains",
        check_params={"pattern": "vulnerabilities|sqli|xss|exec|upload"},
        required=False,
    ),
]

TIER2_FLASK_APP_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="python_identified",
        description="Agent identifies Python/Flask",
        check_type="tech_stack_identified",
        check_params={"keywords": ["python", "flask"]},
        required=True,
    ),
]

TIER2_VULN_LAB_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="languages_identified",
        description="Agent identifies target languages",
        check_type="tech_stack_identified",
        check_params={"keywords": ["python", "javascript", "php"]},
        required=True,
    ),
]


# ── Tier 3: Vulnerability Discovery ───────────────────────────────

TIER3_SYNTHETIC_FLASK_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="sqli_found",
        description="Agent discovers SQL injection vulnerability",
        check_type="vuln_found",
        check_params={"keywords": ["sql injection", "sqli", "SQL\u6ce8\u5165"]},
        required=True,
    ),
    TierCriterion(
        name="xss_found",
        description="Agent discovers XSS vulnerability",
        check_type="vuln_found",
        check_params={"keywords": ["xss", "cross-site scripting", "\u8de8\u7ad9\u811a\u672c"]},
        required=False,
    ),
    TierCriterion(
        name="cmd_injection_found",
        description="Agent discovers command injection vulnerability",
        check_type="vuln_found",
        check_params={"keywords": ["command injection", "os command", "os.system", "\u547d\u4ee4\u6ce8\u5165"]},
        required=False,
    ),
    TierCriterion(
        name="path_traversal_found",
        description="Agent discovers path traversal vulnerability",
        check_type="vuln_found",
        check_params={"keywords": ["path traversal", "directory traversal", "\u8def\u5f84\u904d\u5386"]},
        required=False,
    ),
    TierCriterion(
        name="hardcoded_secret_found",
        description="Agent discovers hardcoded secret",
        check_type="vuln_found",
        check_params={"keywords": ["hardcoded", "secret key", "hardcoded secret", "\u786c\u7f16\u7801"]},
        required=False,
    ),
    TierCriterion(
        name="sqli_in_correct_file",
        description="SQLi finding references app.py",
        check_type="vuln_in_file",
        check_params={"vuln_type": "sql_injection", "file_patterns": ["app.py"]},
        required=False,
    ),
]

TIER3_DVWA_SRC_CRITERIA: List[TierCriterion] = [
    TierCriterion(
        name="sqli_found",
        description="Agent discovers SQL injection in DVWA",
        check_type="vuln_found",
        check_params={"keywords": ["sql injection", "sqli", "SQL\u6ce8\u5165"]},
        required=True,
    ),
    TierCriterion(
        name="xss_found",
        description="Agent discovers XSS in DVWA",
        check_type="vuln_found",
        check_params={"keywords": ["xss", "cross-site scripting"]},
        required=False,
    ),
    TierCriterion(
        name="cmd_injection_found",
        description="Agent discovers command injection in DVWA",
        check_type="vuln_found",
        check_params={"keywords": ["command injection", "os command", "exec"]},
        required=False,
    ),
    TierCriterion(
        name="file_upload_found",
        description="Agent discovers unrestricted file upload in DVWA",
        check_type="vuln_found",
        check_params={"keywords": ["file upload", "unrestricted upload", "arbitrary file"]},
        required=False,
    ),
]


# ── Tier pass thresholds ──────────────────────────────────────────

TIER_PASS_RATES: Dict[int, float] = {
    1: 1.0,   # All criteria must pass for smoke
    2: 0.5,   # 50% pass rate for recon
    3: 0.4,   # 40% pass rate for vuln discovery (harder)
}


# ── Criteria registry ─────────────────────────────────────────────

CRITERIA_REGISTRY: Dict[str, Dict[int, List[TierCriterion]]] = {
    "synthetic-flask": {
        1: TIER1_CRITERIA,
        2: TIER2_SYNTHETIC_FLASK_CRITERIA,
        3: TIER3_SYNTHETIC_FLASK_CRITERIA,
    },
    "vulnerable-flask-app": {
        1: TIER1_CRITERIA,
        2: TIER2_FLASK_APP_CRITERIA,
    },
    "dvwa-src": {
        1: TIER1_CRITERIA,
        2: TIER2_DVWA_SRC_CRITERIA,
        3: TIER3_DVWA_SRC_CRITERIA,
    },
    "security-vuln-lab": {
        1: TIER1_CRITERIA,
        2: TIER2_VULN_LAB_CRITERIA,
    },
    "juice-shop-src": {
        1: TIER1_CRITERIA,
    },
}


def get_criteria(tier: int, target_name: str) -> List[TierCriterion]:
    """Get criteria for a specific tier and target."""
    target_criteria = CRITERIA_REGISTRY.get(target_name, {})
    if tier in target_criteria:
        return target_criteria[tier]
    if tier == 1:
        return TIER1_CRITERIA
    return []
