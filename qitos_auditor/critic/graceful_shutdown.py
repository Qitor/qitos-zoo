"""GracefulShutdownCritic — forces graceful completion when step budget is exhausted.

Based on PentAGI's GracefulShutdownCritic pattern: when the agent is
about to run out of steps, this critic forces a barrier tool call
to deliver whatever results have been gathered.
"""

from __future__ import annotations

from typing import Any

from qitos.core.decision import Decision
from qitos.engine.critic import Critic
from qitos.engine.critic_result import CriticResult


class GracefulShutdownCritic(Critic):
    """Forces graceful completion when step budget is nearly exhausted.

    When the agent has used most of its step budget, this critic
    injects an instruction to call the barrier tool immediately
    with whatever results are available.
    """

    def __init__(self, barrier_tool_name: str = "done", steps_remaining_threshold: int = 2):
        self._barrier_tool_name = barrier_tool_name
        self._steps_remaining_threshold = steps_remaining_threshold

    def evaluate(
        self,
        state: Any,
        observation: Any,
        decision: Decision[Any],
    ) -> CriticResult:
        # Check steps remaining
        steps_taken = getattr(state, "steps_taken", 0)
        max_steps = getattr(state, "max_steps", 100)
        remaining = max_steps - steps_taken

        if remaining <= self._steps_remaining_threshold:
            # Check if the decision already includes a barrier tool call
            actions = getattr(decision, "actions", None) or []
            if isinstance(decision, list):
                actions = decision
            if actions:
                for action in actions:
                    tool_name = getattr(action, "tool_name", getattr(action, "name", ""))
                    if tool_name == self._barrier_tool_name or tool_name.endswith("_result"):
                        return CriticResult(action="continue")

            return CriticResult(
                action="retry",
                reason=f"Step budget nearly exhausted ({remaining} remaining). "
                f"You MUST call {self._barrier_tool_name} immediately.",
                instruction_patch=(
                    f"CRITICAL: You have only {remaining} steps remaining. "
                    f"Call {self._barrier_tool_name} RIGHT NOW with whatever results you have. "
                    f"Do NOT make any more analysis tool calls. "
                    f"Deliver your current findings immediately."
                ),
            )

        return CriticResult(action="continue")
