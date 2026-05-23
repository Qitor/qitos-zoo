"""OrchestratorAgent — manages the overall audit flow and dispatches specialist agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qitos.core.agent_module import AgentModule
from qitos.core.decision import Decision
from qitos.core.state import StateSchema

from ..prompts.orchestrator_prompt import ORCHESTRATOR_SYSTEM_PROMPT
from ..prompts.shared_sections import (
    CORE_SECURITY_PRINCIPLES,
    MULTI_AGENT_RULES,
    TOOL_PLACEHOLDER,
)
from ._reduce_utils import (
    extract_tool_results,
    inject_execution_context,
    inject_handoff_context,
    inject_knowledge_context,
)


@dataclass
class FindingEntry:
    """A single vulnerability finding."""

    id: str = ""
    title: str = ""
    category: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    confidence: float = 0.5
    verdict: str = "uncertain"  # confirmed/likely/uncertain/false_positive
    file: str = ""
    line: int = 0
    evidence: str = ""
    rationale: str = ""
    recommendation: str = ""
    cwe_id: str = ""
    source_agent: str = ""
    poc_result: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "source_agent": self.source_agent,
        }


@dataclass
class HandoffPayload:
    """Structured handoff data between agent phases.

    Aligned with DeepAudit's TaskHandoff — key_findings and suggested_actions
    use structured dicts (with severity/title/file or action/description/priority)
    rather than plain strings.
    """

    summary: str = ""
    key_findings: List[Any] = field(default_factory=list)  # List[str] or List[Dict]
    insights: List[str] = field(default_factory=list)
    suggested_actions: List[Any] = field(default_factory=list)  # List[str] or List[Dict]
    attention_points: List[str] = field(default_factory=list)
    priority_areas: List[str] = field(default_factory=list)
    context_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    from_agent: str = ""
    work_completed: List[str] = field(default_factory=list)

    def to_prompt_context(self) -> str:
        """Format for injection into the next agent's system prompt."""
        parts = [f"### Phase Handoff (from: {self.from_agent or 'unknown'}, confidence: {self.confidence:.0%})"]
        parts.append(f"**Summary**: {self.summary}")
        if self.work_completed:
            parts.append("**Work Completed**:")
            for w in self.work_completed:
                parts.append(f"  - {w}")
        if self.key_findings:
            parts.append("**Key Findings**:")
            for f in self.key_findings:
                if isinstance(f, dict):
                    sev = f.get("severity", "").upper()
                    title = f.get("title", f.get("vulnerability_type", ""))
                    file_path = f.get("file_path", f.get("file", ""))
                    desc = f.get("description", "")[:100]
                    parts.append(f"  - [{sev}] {title} ({file_path}): {desc}" if sev else f"  - {title}: {desc}")
                else:
                    parts.append(f"  - {f}")
        if self.insights:
            parts.append("**Insights**:")
            for i in self.insights:
                parts.append(f"  - {i}")
        if self.suggested_actions:
            parts.append("**Suggested Actions**:")
            for a in self.suggested_actions:
                if isinstance(a, dict):
                    action = a.get("action", "")
                    desc = a.get("description", "")
                    priority = a.get("priority", "")
                    label = f"[{priority.upper()}] {action}: {desc}" if priority else f"{action}: {desc}"
                    parts.append(f"  - {label}")
                else:
                    parts.append(f"  - {a}")
        if self.attention_points:
            parts.append("**Attention Points**:")
            for a in self.attention_points:
                parts.append(f"  - {a}")
        if self.priority_areas:
            parts.append("**Priority Areas**:")
            for p in self.priority_areas:
                parts.append(f"  - {p}")
        if self.context_data:
            import json
            parts.append(f"**Context Data**: {json.dumps(self.context_data, indent=2, default=str)[:2000]}")
        return "\n".join(parts)


@dataclass
class OrchestratorState(StateSchema):
    """State for the OrchestratorAgent."""

    current_phase: str = "recon"  # recon -> analysis -> verification -> reporting
    target_path: str = ""
    tech_stack: Dict[str, str] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    handoffs: Dict[str, Any] = field(default_factory=dict)
    report: str = ""
    phase_dispatched: Dict[str, int] = field(default_factory=dict)


class OrchestratorAgent(AgentModule[OrchestratorState, Any, Any]):
    """Orchestrator agent — manages the overall audit flow.

    Dispatches specialist agents (Recon, Analysis, Verification) in
    sequence and synthesizes their results into a final audit report.
    """

    name = "orchestrator"

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

    def init_state(self, task: str, **kwargs: Any) -> OrchestratorState:
        max_steps = kwargs.get("max_steps", 20)
        return OrchestratorState(
            task=task,
            max_steps=max_steps,
            target_path=self.target_path,
        )

    def build_system_prompt(self, state: OrchestratorState) -> str | None:
        prompt = ORCHESTRATOR_SYSTEM_PROMPT + "\n\n" + CORE_SECURITY_PRINCIPLES + "\n\n" + MULTI_AGENT_RULES

        prompt = prompt.format(
            current_phase=state.current_phase,
            target_path=state.target_path,
            recon_completed="Yes" if "recon" in state.handoffs else "No",
            analysis_completed="Yes" if "analysis" in state.handoffs else "No",
            verification_completed="Yes" if "verification" in state.handoffs else "No",
            findings_count=len(state.findings),
            tool_placeholder=TOOL_PLACEHOLDER,
        )

        # Inject execution context
        prompt = inject_execution_context(self, prompt)
        prompt = inject_knowledge_context(self, prompt)

        # Append handoff summaries from completed phases
        for phase, handoff_data in state.handoffs.items():
            if isinstance(handoff_data, dict):
                handoff = HandoffPayload(**{k: v for k, v in handoff_data.items() if k in HandoffPayload.__dataclass_fields__})
                prompt += f"\n\n# {phase.title()} Phase Results\n{handoff.to_prompt_context()}"

        return prompt

    def reduce(
        self,
        state: OrchestratorState,
        observation: Any,
        decision: Decision[Any],
    ) -> OrchestratorState:
        tool_results = extract_tool_results(observation)

        for tool_name, result in tool_results.items():
            if tool_name == "done":
                state.report = result.get("summary", "")
                state.current_phase = "done"
            elif tool_name in ("delegate_to_recon", "delegate_to_analysis", "delegate_to_verification"):
                phase = tool_name.replace("delegate_to_", "")
                state.phase_dispatched[phase] = state.phase_dispatched.get(phase, 0) + 1
            elif tool_name in ("recon_result", "analysis_result", "verification_result"):
                phase = result.get("phase", tool_name.replace("_result", ""))
                state.handoffs[phase] = result
                # Extract findings from handoff context_data
                context = result.get("context_data", {})
                for f in context.get("findings", []):
                    if isinstance(f, dict):
                        state.findings.append(f)
                # Update tech stack from recon
                if phase == "recon":
                    state.tech_stack = context.get("tech_stack", {})
                    state.entry_points = context.get("entry_points", [])
                # Advance phase
                if phase == "recon":
                    state.current_phase = "analysis"
                elif phase == "analysis":
                    state.current_phase = "verification"
                elif phase == "verification":
                    state.current_phase = "reporting"

        return state

    def should_stop(self, state: OrchestratorState) -> bool:
        return state.current_phase == "done"
