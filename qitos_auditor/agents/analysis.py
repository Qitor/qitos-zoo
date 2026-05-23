"""AnalysisAgent — vulnerability detection specialist."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qitos.core.agent_module import AgentModule
from qitos.core.decision import Decision
from qitos.core.state import StateSchema

from ..prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT
from ..prompts.shared_sections import (
    CORE_SECURITY_PRINCIPLES,
    VULNERABILITY_PRIORITIES,
    FILE_VALIDATION_RULES_V2_1,
    TOOL_PLACEHOLDER,
)
from ._reduce_utils import (
    extract_tool_results,
    inject_execution_context,
    inject_handoff_context,
    inject_knowledge_context,
    parse_finding_from_tool_output,
)


@dataclass
class AnalysisState(StateSchema):
    """State for the AnalysisAgent."""

    target_path: str = ""
    tech_stack: Dict[str, str] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    scanner_results: Dict[str, Any] = field(default_factory=dict)
    analyzed_files: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    handoff: Optional[Dict[str, Any]] = None
    tool_call_counts: Dict[str, int] = field(default_factory=dict)


class AnalysisAgent(AgentModule[AnalysisState, Any, Any]):
    """Vulnerability analysis specialist agent.

    Runs external scanners (semgrep, bandit, gitleaks) first, then
    performs deep manual analysis. Documents all findings with evidence.
    """

    name = "analysis"

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

    def init_state(self, task: str, **kwargs: Any) -> AnalysisState:
        max_steps = kwargs.get("max_steps", 30)
        return AnalysisState(
            task=task,
            max_steps=max_steps,
            target_path=self.target_path,
        )

    def build_system_prompt(self, state: AnalysisState) -> str | None:
        prompt = (
            ANALYSIS_SYSTEM_PROMPT
            + "\n\n"
            + CORE_SECURITY_PRINCIPLES
            + "\n\n"
            + VULNERABILITY_PRIORITIES
            + "\n\n"
            + FILE_VALIDATION_RULES_V2_1
        )
        prompt = prompt.format(tool_placeholder=TOOL_PLACEHOLDER)

        # Inject execution context and handoff from recon
        prompt = inject_execution_context(self, prompt)
        prompt = inject_handoff_context(self, prompt)
        prompt = inject_knowledge_context(self, prompt)

        # Add findings count context
        if state.findings:
            prompt += f"\n\n## Current Findings: {len(state.findings)} recorded"

        return prompt

    def reduce(
        self,
        state: AnalysisState,
        observation: Any,
        decision: Decision[Any],
    ) -> AnalysisState:
        tool_results = extract_tool_results(observation)

        for tool_name, result in tool_results.items():
            # Track tool call counts for repeated call detection
            state.tool_call_counts[tool_name] = state.tool_call_counts.get(tool_name, 0) + 1

            if tool_name == "read_file":
                path = result.get("file_path", result.get("path", ""))
                if path and path not in state.files_read:
                    state.files_read.append(path)
            elif tool_name == "analysis_result":
                state.handoff = result
                # Extract findings from context_data
                ctx = result.get("context_data", {})
                if ctx.get("findings"):
                    for f in ctx["findings"]:
                        if isinstance(f, dict) and f not in state.findings:
                            state.findings.append(f)
            elif tool_name == "create_vulnerability_report":
                finding = parse_finding_from_tool_output(result)
                if finding:
                    state.findings.append(finding)
                elif isinstance(result, dict) and result.get("status") == "recorded":
                    state.findings.append(result)
            elif tool_name in ("semgrep_scan", "bandit_scan", "gitleaks_scan",
                               "safety_check", "npm_audit", "osv_scanner",
                               "kunlun_scan", "trufflehog_scan"):
                state.scanner_results[tool_name] = result

        return state

    def should_stop(self, state: AnalysisState) -> bool:
        return state.handoff is not None
