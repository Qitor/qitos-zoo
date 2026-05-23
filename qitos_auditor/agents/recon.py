"""ReconAgent — reconnaissance specialist for project scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qitos.core.agent_module import AgentModule
from qitos.core.decision import Decision
from qitos.core.state import StateSchema

from ..prompts.recon_prompt import RECON_SYSTEM_PROMPT
from ..prompts.shared_sections import TOOL_USAGE_GUIDE, TOOL_PLACEHOLDER
from ._reduce_utils import (
    extract_tool_results,
    inject_execution_context,
    inject_handoff_context,
    inject_knowledge_context,
)


@dataclass
class ReconState(StateSchema):
    """State for the ReconAgent."""

    target_path: str = ""
    tech_stack: Dict[str, str] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    file_inventory: Dict[str, Any] = field(default_factory=dict)
    dependency_inventory: Dict[str, Any] = field(default_factory=dict)
    framework_hints: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    scan_results: List[Dict[str, Any]] = field(default_factory=list)
    handoff: Optional[Dict[str, Any]] = None


class ReconAgent(AgentModule[ReconState, Any, Any]):
    """Reconnaissance specialist agent.

    Scans project structure, identifies tech stack, discovers
    entry points, and recommends security tools for the analysis phase.
    """

    name = "recon"

    def __init__(
        self,
        llm: Any = None,
        tool_registry: Any = None,
        target_path: str = ".",
        **config: Any,
    ):
        super().__init__(
            llm=llm,
            tool_registry=tool_registry,
            **config,
        )
        self.target_path = target_path

    def init_state(self, task: str, **kwargs: Any) -> ReconState:
        max_steps = kwargs.get("max_steps", 15)
        return ReconState(
            task=task,
            max_steps=max_steps,
            target_path=self.target_path,
        )

    def build_system_prompt(self, state: ReconState) -> str | None:
        prompt = RECON_SYSTEM_PROMPT + "\n\n" + TOOL_USAGE_GUIDE
        prompt = prompt.format(tool_placeholder=TOOL_PLACEHOLDER)

        # Inject execution context
        prompt = inject_execution_context(self, prompt)
        prompt = inject_handoff_context(self, prompt)
        prompt = inject_knowledge_context(self, prompt)

        return prompt

    def reduce(
        self,
        state: ReconState,
        observation: Any,
        decision: Decision[Any],
    ) -> ReconState:
        tool_results = extract_tool_results(observation)

        for tool_name, result in tool_results.items():
            if tool_name == "read_file":
                path = result.get("file_path", result.get("path", ""))
                if path and path not in state.files_read:
                    state.files_read.append(path)
            elif tool_name == "recon_result":
                state.handoff = result
                # Extract tech_stack and entry_points from context_data
                ctx = result.get("context_data", {})
                if ctx.get("tech_stack"):
                    state.tech_stack = ctx["tech_stack"]
                if ctx.get("entry_points"):
                    state.entry_points = ctx["entry_points"]
            elif tool_name in ("smart_scan", "pattern_match", "semgrep_scan",
                               "bandit_scan", "gitleaks_scan"):
                state.scan_results.append({"tool": tool_name, "result": result})

        return state

    def should_stop(self, state: ReconState) -> bool:
        return state.handoff is not None
