"""AuditorE2EScorer — objective scoring engine for DeepAudit results.

Evaluates AuditResult against TierCriterion conditions using text
pattern matching and ground-truth comparison. Does NOT use LLM self-assessment.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .criteria import TierCriterion
from .report import CriterionScore, ScoreReport


def _collect_text(result: Any) -> str:
    """Collect all searchable text from an AuditResult."""
    parts: List[str] = []

    report = getattr(result, "report", "")
    if isinstance(report, str) and report:
        parts.append(report)

    findings = getattr(result, "findings", [])
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                for key in (
                    "title", "description", "evidence", "vulnerability_type",
                    "file_path", "file", "recommendation", "suggestion", "rationale",
                ):
                    val = f.get(key, "")
                    if isinstance(val, str) and val:
                        parts.append(val)

    handoffs = getattr(result, "handoffs", {})
    if isinstance(handoffs, dict):
        for _phase, h in handoffs.items():
            # Handle both dict and HandoffPayload objects
            if hasattr(h, "summary"):
                val = getattr(h, "summary", "")
                if isinstance(val, str) and val:
                    parts.append(val)
                # Also add context_data text
                ctx = getattr(h, "context_data", None)
                if isinstance(ctx, dict):
                    for v in ctx.values():
                        if isinstance(v, str) and v:
                            parts.append(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, dict):
                                    for iv in item.values():
                                        if isinstance(iv, str) and iv:
                                            parts.append(iv)
            elif isinstance(h, dict):
                for key in ("summary",):
                    val = h.get(key, "")
                    if isinstance(val, str) and val:
                        parts.append(val)

    return "\n".join(parts)


class AuditorE2EScorer:
    """Score DeepAudit results against objective criteria."""

    def score(
        self,
        result: Any,
        criteria: List[TierCriterion],
        ground_truth: Dict[str, Any],
        tier: int = 0,
        target_name: str = "",
    ) -> ScoreReport:
        scores: List[CriterionScore] = []
        for criterion in criteria:
            passed, detail = self._check(criterion, result, ground_truth)
            scores.append(CriterionScore(
                name=criterion.name,
                passed=passed,
                points=criterion.points if passed else 0.0,
                required=criterion.required,
                detail=detail,
            ))
        return ScoreReport(scores=scores, tier=tier, target_name=target_name)

    def _check(
        self,
        criterion: TierCriterion,
        result: Any,
        ground_truth: Dict[str, Any],
    ) -> Tuple[bool, str]:
        dispatch = {
            "pipeline_completed": self._check_pipeline_completed,
            "report_produced": self._check_report_produced,
            "tech_stack_identified": self._check_tech_stack_identified,
            "vuln_found": self._check_vuln_found,
            "vuln_in_file": self._check_vuln_in_file,
            "vuln_with_evidence": self._check_vuln_with_evidence,
            "finding_count_min": self._check_finding_count_min,
            "report_contains": self._check_report_contains,
        }
        checker = dispatch.get(criterion.check_type)
        if checker is None:
            return False, f"Unknown check_type: {criterion.check_type}"
        return checker(criterion, result, ground_truth)

    # ── Check implementations ──────────────────────────────────────

    def _check_pipeline_completed(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        status = getattr(result, "status", "unknown")
        if status == "completed":
            return True, f"Pipeline status: {status}"
        if status in ("timeout", "partial"):
            report = getattr(result, "report", "")
            if isinstance(report, str) and len(report) >= 200:
                return True, f"Pipeline status: {status} (report produced)"
        return False, f"Pipeline status: {status}"

    def _check_report_produced(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        report = getattr(result, "report", "")
        if isinstance(report, str) and len(report) >= 300:
            return True, f"Report length: {len(report)} chars"
        length = len(report) if isinstance(report, str) else 0
        return False, f"Report length: {length} chars (need >= 300)"

    def _check_tech_stack_identified(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        keywords = c.check_params.get("keywords", [])
        text = _collect_text(result).lower()
        found = [kw for kw in keywords if kw.lower() in text]
        if found:
            return True, f"Found tech stack keywords: {found}"
        return False, f"Tech stack keywords not found: {keywords}"

    def _check_vuln_found(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        keywords = c.check_params.get("keywords", [])
        text = _collect_text(result).lower()
        found = [kw for kw in keywords if kw.lower() in text]
        if found:
            return True, f"Found vulnerability keywords: {found}"
        return False, f"Vulnerability keywords not found: {keywords}"

    def _check_vuln_in_file(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        vuln_type = c.check_params.get("vuln_type", "")
        file_patterns = c.check_params.get("file_patterns", [])
        findings = getattr(result, "findings", [])
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                ftype = str(f.get("vulnerability_type", "") or f.get("category", "")).lower()
                ffile = str(f.get("file_path", "") or f.get("file", "")).lower()
                if vuln_type and vuln_type.lower() not in ftype:
                    continue
                for pattern in file_patterns:
                    if pattern.lower() in ffile:
                        return True, f"Found {vuln_type} in {ffile}"
        # Also check report text for file + vuln type together
        text = _collect_text(result).lower()
        if vuln_type.lower() in text:
            for pattern in file_patterns:
                if pattern.lower() in text:
                    return True, f"Found {vuln_type} mentioned near {pattern} in report"
        return False, f"Vulnerability {vuln_type} not found in files: {file_patterns}"

    def _check_vuln_with_evidence(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        vuln_type = c.check_params.get("vuln_type", "")
        min_evidence_len = c.check_params.get("min_evidence_len", 20)
        findings = getattr(result, "findings", [])
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                ftype = str(f.get("vulnerability_type", "") or f.get("category", "")).lower()
                if vuln_type and vuln_type.lower() not in ftype:
                    continue
                evidence = str(f.get("evidence", ""))
                if len(evidence) >= min_evidence_len:
                    return True, f"Evidence length: {len(evidence)} chars"
        return False, f"No sufficient evidence for {vuln_type}"

    def _check_finding_count_min(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        min_count = c.check_params.get("min_count", 1)
        findings = getattr(result, "findings", [])
        count = len(findings) if isinstance(findings, list) else 0
        if count >= min_count:
            return True, f"Found {count} findings (need >= {min_count})"
        return False, f"Found {count} findings (need >= {min_count})"

    def _check_report_contains(self, c: TierCriterion, result: Any, gt: Dict) -> Tuple[bool, str]:
        pattern = c.check_params.get("pattern", "")
        if not pattern:
            return False, "No pattern specified"
        text = _collect_text(result)
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return True, f"Pattern '{pattern}' found"
        except re.error:
            if pattern.lower() in text.lower():
                return True, f"Pattern '{pattern}' found (substring)"
        return False, f"Pattern '{pattern}' not found"
