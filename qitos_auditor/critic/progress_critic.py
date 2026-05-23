"""AuditProgressCritic — monitors audit progress and suggests direction changes.

When an agent makes multiple consecutive steps without producing new
findings or meaningful progress, this critic suggests switching to
a different area of analysis.
"""

from __future__ import annotations

from typing import Any, List

from qitos.core.decision import Decision
from qitos.engine.critic import Critic
from qitos.engine.critic_result import CriticResult


class AuditProgressCritic(Critic):
    """Monitors audit progress and suggests direction changes.

    Tracks consecutive steps without new findings and suggests
    switching focus when the agent appears stuck in a rut.
    """

    def __init__(self, stagnation_threshold: int = 5):
        self._stagnation_threshold = stagnation_threshold
        self._steps_without_progress = 0
        self._last_finding_count = 0

    def evaluate(
        self,
        state: Any,
        observation: Any,
        decision: Decision[Any],
    ) -> CriticResult:
        # Count current findings
        current_findings = 0
        if hasattr(state, "findings"):
            current_findings = len(state.findings) if isinstance(state.findings, list) else 0
        elif hasattr(state, "verified_findings"):
            current_findings = len(state.verified_findings) if isinstance(state.verified_findings, list) else 0

        # Check if we made progress
        if current_findings > self._last_finding_count:
            self._steps_without_progress = 0
            self._last_finding_count = current_findings
        else:
            self._steps_without_progress += 1

        # Suggest direction change if stagnant
        if self._steps_without_progress >= self._stagnation_threshold:
            self._steps_without_progress = 0  # Reset after suggestion

            return CriticResult(
                action="continue",  # Don't block, just advise
                reason=f"No new findings in {self._stagnation_threshold} steps.",
                instruction_patch=(
                    "PROGRESS NOTE: You haven't made new discoveries recently. "
                    "Consider:\n"
                    "1. Switching to a different file or directory\n"
                    "2. Trying a different vulnerability category\n"
                    "3. Running a different scanner tool\n"
                    "4. If you've covered all important areas, deliver your results"
                ),
            )

        return CriticResult(action="continue")
