"""EmptyResponseCritic — handles empty LLM API responses.

When the LLM returns an empty response, this critic triggers a retry
with a prompt encouraging the agent to continue.
"""

from __future__ import annotations

from typing import Any

from qitos.core.decision import Decision
from qitos.engine.critic import Critic
from qitos.engine.critic_result import CriticResult


class EmptyResponseCritic(Critic):
    """Handles empty LLM API responses with retries.

    If the LLM returns an empty or whitespace-only response,
    this critic triggers a retry with a guidance prompt.
    After max_retries, forces graceful shutdown.
    """

    def __init__(self, max_retries: int = 3):
        self._max_retries = max_retries
        self._retry_count = 0

    def evaluate(
        self,
        state: Any,
        observation: Any,
        decision: Decision[Any],
    ) -> CriticResult:
        # Check if the decision is empty (no rationale, no actions)
        rationale = getattr(decision, "rationale", "") or ""
        actions = getattr(decision, "actions", None) or []

        if not rationale.strip() and not actions:
            self._retry_count += 1

            if self._retry_count > self._max_retries:
                return CriticResult(
                    action="retry",
                    reason="Empty response limit exceeded. Forcing completion.",
                    instruction_patch="Call your barrier tool immediately to complete the current phase with whatever results you have.",
                )

            return CriticResult(
                action="retry",
                reason=f"Empty LLM response (attempt {self._retry_count}/{self._max_retries}).",
                instruction_patch=(
                    "You received an empty response. Please try again. "
                    "If you have gathered enough information, call your barrier tool "
                    "to deliver your results."
                ),
            )

        # Reset retry count on successful response
        self._retry_count = 0
        return CriticResult(action="continue")
