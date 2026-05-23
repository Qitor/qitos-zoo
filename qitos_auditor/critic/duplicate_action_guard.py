"""RepeatedToolCallCritic — detects and prevents repeated tool calls.

When an agent makes the same tool call with identical arguments more
than 2 times, this critic forces a strategy change.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from qitos.core.decision import Decision
from qitos.engine.critic import Critic
from qitos.engine.critic_result import CriticResult


class RepeatedToolCallCritic(Critic):
    """Detects repeated identical tool calls and forces strategy change.

    If the same tool is called with the same arguments more than
    max_repeats times, the critic blocks the call and suggests
    trying a different approach.
    """

    def __init__(self, max_repeats: int = 2):
        self._max_repeats = max_repeats
        self._call_history: Dict[str, int] = {}

    def evaluate(
        self,
        state: Any,
        observation: Any,
        decision: Decision[Any],
    ) -> CriticResult:
        actions = getattr(decision, "actions", None) or []
        if isinstance(decision, list):
            actions = decision
        if not actions:
            return CriticResult(action="continue")

        for action in actions:
            # Build a fingerprint from tool name + args
            tool_name = getattr(action, "tool_name", getattr(action, "name", ""))
            args = getattr(action, "args", {})
            if isinstance(args, dict):
                # Sort keys for consistent fingerprinting
                args_str = str(sorted(args.items()))
            else:
                args_str = str(args)

            fingerprint = f"{tool_name}:{args_str}"
            self._call_history[fingerprint] = self._call_history.get(fingerprint, 0) + 1

            if self._call_history[fingerprint] > self._max_repeats:
                return CriticResult(
                    action="retry",
                    reason=f"Repeated tool call detected: {tool_name} has been called "
                    f"{self._call_history[fingerprint]} times with the same arguments. "
                    f"This suggests the approach is not working.",
                    instruction_patch=(
                        f"Try a different approach. The tool {tool_name} is not producing "
                        f"useful results with these arguments. Consider:\n"
                        f"1. Using a different tool\n"
                        f"2. Changing the arguments\n"
                        f"3. Moving on to the next area of analysis"
                    ),
                )

        return CriticResult(action="continue")
