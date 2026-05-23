"""VerificationAgent — finding validation and PoC testing specialist."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qitos.core.agent_module import AgentModule
from qitos.core.decision import Decision
from qitos.core.state import StateSchema

from ..prompts.verification_prompt import VERIFICATION_SYSTEM_PROMPT
from ..prompts.shared_sections import (
    CORE_SECURITY_PRINCIPLES,
    VULNERABILITY_PRIORITIES,
    FILE_VALIDATION_RULES_V2_1,
    VERIFICATION_VERDICT_CRITERIA,
    TOOL_PLACEHOLDER,
)
from ._reduce_utils import (
    extract_tool_results,
    inject_execution_context,
    inject_handoff_context,
    inject_knowledge_context,
)


@dataclass
class VerificationState(StateSchema):
    """State for the VerificationAgent."""

    target_path: str = ""
    findings_to_verify: List[Dict[str, Any]] = field(default_factory=list)
    verified_findings: List[Dict[str, Any]] = field(default_factory=list)
    poc_results: Dict[str, Any] = field(default_factory=dict)
    sandbox_available: bool = False
    files_read: List[str] = field(default_factory=list)
    handoff: Optional[Dict[str, Any]] = None
    tool_call_counts: Dict[str, int] = field(default_factory=dict)
    verified_count: int = 0
    confirmed_count: int = 0
    false_positive_count: int = 0


class VerificationAgent(AgentModule[VerificationState, Any, Any]):
    """Verification specialist agent.

    Validates findings from the Analysis agent via PoC testing,
    assigns verdicts (confirmed/likely/uncertain/false_positive),
    and generates repair recommendations.
    """

    name = "verification"

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

    def init_state(self, task: str, **kwargs: Any) -> VerificationState:
        max_steps = kwargs.get("max_steps", 25)
        return VerificationState(
            task=task,
            max_steps=max_steps,
            target_path=self.target_path,
        )

    def build_system_prompt(self, state: VerificationState) -> str | None:
        prompt = (
            VERIFICATION_SYSTEM_PROMPT
            + "\n\n"
            + CORE_SECURITY_PRINCIPLES
            + "\n\n"
            + VULNERABILITY_PRIORITIES
            + "\n\n"
            + FILE_VALIDATION_RULES_V2_1
            + "\n\n"
            + VERIFICATION_VERDICT_CRITERIA
        )
        prompt = prompt.format(tool_placeholder=TOOL_PLACEHOLDER)

        # Inject execution context and handoff from analysis
        prompt = inject_execution_context(self, prompt)
        prompt = inject_handoff_context(self, prompt)
        prompt = inject_knowledge_context(self, prompt)

        # Add verification progress
        if state.verified_findings:
            prompt += f"\n\n## Verification Progress: {len(state.verified_findings)}/{len(state.findings_to_verify)} verified"
            prompt += f" (Confirmed: {state.confirmed_count}, False Positive: {state.false_positive_count})"

        return prompt

    def reduce(
        self,
        state: VerificationState,
        observation: Any,
        decision: Decision[Any],
    ) -> VerificationState:
        tool_results = extract_tool_results(observation)

        for tool_name, result in tool_results.items():
            # Track tool call counts
            state.tool_call_counts[tool_name] = state.tool_call_counts.get(tool_name, 0) + 1

            if tool_name == "read_file":
                path = result.get("file_path", result.get("path", ""))
                if path and path not in state.files_read:
                    state.files_read.append(path)
            elif tool_name == "verification_result":
                state.handoff = result
                # Extract verified findings from context_data
                ctx = result.get("context_data", {})
                for f in ctx.get("verified_findings", []):
                    if isinstance(f, dict):
                        state.verified_findings.append(f)
                        if f.get("verdict") == "confirmed":
                            state.confirmed_count += 1
                        elif f.get("verdict") == "false_positive":
                            state.false_positive_count += 1
            elif tool_name == "vulnerability_validation":
                if isinstance(result, dict):
                    state.verified_findings.append(result)
                    state.verified_count += 1
                    if result.get("verdict") == "confirmed":
                        state.confirmed_count += 1
                    elif result.get("verdict") == "false_positive":
                        state.false_positive_count += 1
            elif tool_name in ("run_code", "sandbox_exec", "sandbox_http"):
                # Store PoC results
                poc_id = f"poc_{len(state.poc_results)}"
                state.poc_results[poc_id] = {
                    "tool": tool_name,
                    "exit_code": result.get("exit_code", -1),
                    "vulnerable": bool(result.get("vulnerability_indicators", [])),
                }
            elif tool_name in ("test_command_injection", "test_sql_injection", "test_xss",
                               "test_path_traversal", "test_ssti", "test_deserialization",
                               "vuln_test"):
                # Store injection test results
                poc_id = f"test_{len(state.poc_results)}"
                state.poc_results[poc_id] = {
                    "tool": tool_name,
                    "vulnerable": result.get("vulnerable", False),
                    "evidence": result.get("evidence", []),
                }

        return state

    def should_stop(self, state: VerificationState) -> bool:
        return state.handoff is not None
