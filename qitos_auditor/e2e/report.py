"""ScoreReport — structured output from DeepAudit e2e scoring.

Reuses the same structure as pentagi's ScoreReport for consistency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CriterionScore:
    """Score result for a single criterion."""

    name: str
    passed: bool
    points: float
    required: bool
    detail: str = ""


@dataclass
class ScoreReport:
    """Aggregated score report for a DeepAudit e2e test run."""

    scores: List[CriterionScore] = field(default_factory=list)
    tier: int = 0
    target_name: str = ""

    @property
    def total_points(self) -> float:
        return sum(s.points for s in self.scores)

    @property
    def earned_points(self) -> float:
        return sum(s.points for s in self.scores if s.passed)

    @property
    def pass_rate(self) -> float:
        if not self.scores:
            return 0.0
        return sum(1 for s in self.scores if s.passed) / len(self.scores)

    @property
    def required_passed(self) -> bool:
        return all(s.passed for s in self.scores if s.required)

    @property
    def failure_reasons(self) -> List[str]:
        return [s.name for s in self.scores if s.required and not s.passed]

    def tier_passed(self, pass_rate_threshold: float = 1.0) -> bool:
        return self.required_passed and self.pass_rate >= pass_rate_threshold

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier,
            "target_name": self.target_name,
            "pass_rate": self.pass_rate,
            "required_passed": self.required_passed,
            "total_points": self.total_points,
            "earned_points": self.earned_points,
            "failure_reasons": self.failure_reasons,
            "scores": [
                {
                    "name": s.name,
                    "passed": s.passed,
                    "points": s.points,
                    "required": s.required,
                    "detail": s.detail,
                }
                for s in self.scores
            ],
        }

    def summary(self) -> str:
        lines = [
            f"DeepAudit E2E Score Report — Tier {self.tier} / {self.target_name}",
            f"Pass rate: {self.pass_rate:.0%} | Required: {'PASS' if self.required_passed else 'FAIL'}",
            f"Points: {self.earned_points}/{self.total_points}",
            "",
        ]
        for s in self.scores:
            status = "PASS" if s.passed else "FAIL"
            req = " [required]" if s.required else ""
            lines.append(f"  [{status}] {s.name}{req}")
            if s.detail:
                lines.append(f"         {s.detail}")
        if self.failure_reasons:
            lines.append(f"\nFailed required: {', '.join(self.failure_reasons)}")
        return "\n".join(lines)
