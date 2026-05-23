"""Thinking and reflection tools for audit agents.

- ThinkTool: Record reasoning and analysis progress
- ReflectTool: Reflect on current progress and adjust strategy
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


class ThinkTool(BaseTool):
    """Record reasoning and analysis progress during an audit.

    Use this to organize your thoughts before taking action, especially
    when facing complex analysis decisions or planning multi-step strategies.
    """

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="think",
                description="Record your reasoning about a finding or analysis decision. "
                "Use this to organize your thoughts before taking action. "
                "This does NOT produce external output — it structures your thinking.",
                parameters={
                    "thought": {
                        "type": "string",
                        "description": "Your reasoning or analysis",
                    },
                    "category": {
                        "type": "string",
                        "description": "Category of thought: analysis, hypothesis, strategy, concern, conclusion",
                    },
                },
                required=["thought"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        thought = args.get("thought", "")
        category = args.get("category", "analysis")
        valid_categories = {"analysis", "hypothesis", "strategy", "concern", "conclusion"}
        if category not in valid_categories:
            category = "analysis"

        return {
            "recorded": True,
            "category": category,
            "thought_length": len(thought),
        }


class ReflectTool(BaseTool):
    """Reflect on current audit progress and adjust strategy.

    Use this periodically to assess what you've done, what remains,
    and whether your approach needs adjustment.
    """

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="reflect",
                description="Reflect on your current progress and adjust your audit strategy. "
                "Use this to evaluate what you've accomplished and what still needs to be done.",
                parameters={
                    "accomplished": {
                        "type": "string",
                        "description": "What you have accomplished so far",
                    },
                    "remaining": {
                        "type": "string",
                        "description": "What still needs to be done",
                    },
                    "concerns": {
                        "type": "string",
                        "description": "Any concerns or blockers",
                    },
                    "next_action": {
                        "type": "string",
                        "description": "What you plan to do next",
                    },
                },
                required=["accomplished", "remaining"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return {
            "reflection_recorded": True,
            "accomplished": args.get("accomplished", ""),
            "remaining": args.get("remaining", ""),
            "concerns": args.get("concerns", ""),
            "next_action": args.get("next_action", ""),
        }
