"""PhaseManager — manages phase transitions in the audit pipeline."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..agents.orchestrator import HandoffPayload


PHASES = ["recon", "analysis", "verification", "reporting"]

# Severity ordering for sorting findings
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class PhaseManager:
    """Manages phase transitions and handoff data in the audit pipeline.

    Tracks which phases have been completed, stores handoffs, and builds
    rich, targeted handoffs for the next phase — aligned with DeepAudit's
    _build_handoff_for_agent() pattern.
    """

    def __init__(self):
        self._completed_phases: Dict[str, HandoffPayload] = {}
        self._current_phase: str = "recon"

    @property
    def current_phase(self) -> str:
        return self._current_phase

    def complete_phase(self, phase: str, handoff: HandoffPayload) -> None:
        """Mark a phase as completed and store its handoff data."""
        self._completed_phases[phase] = handoff
        idx = PHASES.index(phase) if phase in PHASES else -1
        if idx >= 0 and idx < len(PHASES) - 1:
            self._current_phase = PHASES[idx + 1]

    def get_handoff(self, phase: str) -> Optional[HandoffPayload]:
        """Get handoff data from a completed phase."""
        return self._completed_phases.get(phase)

    def get_previous_handoff(self) -> Optional[HandoffPayload]:
        """Get handoff data from the most recently completed phase."""
        if not self._completed_phases:
            return None
        idx = PHASES.index(self._current_phase) if self._current_phase in PHASES else 0
        if idx > 0:
            return self._completed_phases.get(PHASES[idx - 1])
        return None

    def get_all_handoffs(self) -> Dict[str, HandoffPayload]:
        """Get all completed phase handoffs."""
        return dict(self._completed_phases)

    def is_phase_completed(self, phase: str) -> bool:
        return phase in self._completed_phases

    def is_complete(self) -> bool:
        return self._current_phase == "reporting" and "verification" in self._completed_phases

    def build_handoff_for_phase(self, target_phase: str) -> Optional[HandoffPayload]:
        """Build a rich, targeted HandoffPayload for the next phase.

        Aligns with DeepAudit's _build_handoff_for_agent() — merges context
        from prior phases and structures findings/actions for the target agent.
        """
        if target_phase == "analysis":
            return self._build_analysis_handoff()
        elif target_phase == "verification":
            return self._build_verification_handoff()
        elif target_phase == "reporting":
            return self._build_reporting_handoff()
        return None

    def _build_analysis_handoff(self) -> Optional[HandoffPayload]:
        """Build handoff for Analysis phase from Recon results."""
        recon = self.get_handoff("recon")
        if not recon:
            return None

        ctx = dict(recon.context_data)
        key_findings = list(recon.key_findings) if recon.key_findings else []
        suggested_actions = list(recon.suggested_actions) if recon.suggested_actions else []

        # Extract initial_findings as key_findings if present
        initial = ctx.get("initial_findings", [])
        if initial and not key_findings:
            for f in initial[:15]:
                if isinstance(f, dict):
                    key_findings.append(f)
                else:
                    key_findings.append(str(f))

        # Extract high_risk_areas as priority_areas and suggested_actions
        high_risk = ctx.get("high_risk_areas", [])
        if high_risk:
            for area in high_risk[:15]:
                if isinstance(area, str):
                    suggested_actions.append({"action": "deep_analysis", "description": area, "priority": "high"})

        # Extract recommended_tools into context
        recommended = ctx.get("recommended_tools", {})
        if recommended:
            ctx["recommended_tools"] = recommended

        return HandoffPayload(
            summary=f"Recon completed. {len(key_findings)} initial findings, {len(high_risk)} high-risk areas.",
            key_findings=key_findings[:15],
            insights=list(recon.insights),
            suggested_actions=suggested_actions[:20],
            attention_points=list(recon.attention_points),
            priority_areas=[a if isinstance(a, str) else str(a) for a in high_risk[:15]],
            context_data=ctx,
            confidence=recon.confidence,
            from_agent="recon",
            work_completed=list(recon.work_completed) if recon.work_completed else [recon.summary],
        )

    def _build_verification_handoff(self) -> Optional[HandoffPayload]:
        """Build handoff for Verification phase from Analysis + Recon results."""
        analysis = self.get_handoff("analysis")
        recon = self.get_handoff("recon")
        if not analysis:
            return None

        # Merge context from both Recon and Analysis
        ctx = dict(analysis.context_data)
        if recon:
            ctx["tech_stack"] = recon.context_data.get("tech_stack", {})
            ctx["entry_points"] = recon.context_data.get("entry_points", [])

        # Sort findings by severity
        findings = list(analysis.key_findings) if analysis.key_findings else []
        ctx_findings = ctx.get("findings", [])
        all_findings = findings + [f for f in ctx_findings if isinstance(f, dict)]

        def severity_key(f):
            if isinstance(f, dict):
                return _SEVERITY_ORDER.get(f.get("severity", "medium").lower(), 2)
            return 2

        all_findings.sort(key=severity_key)

        # Top 15 findings
        key_findings = all_findings[:15]

        # Build suggested_actions for verification
        suggested_actions = []
        for f in key_findings[:10]:
            if isinstance(f, dict):
                sev = f.get("severity", "medium")
                title = f.get("title", f.get("vulnerability_type", "unknown"))
                suggested_actions.append({
                    "action": "verify",
                    "description": title,
                    "priority": sev,
                })

        # Severity distribution insights
        sev_counts: Dict[str, int] = {}
        for f in all_findings:
            if isinstance(f, dict):
                sev = f.get("severity", "medium").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
        insights = list(analysis.insights)
        if sev_counts:
            dist = ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: _SEVERITY_ORDER.get(x[0], 2)))
            insights.append(f"Severity distribution: {dist}")

        # Files with most findings → attention_points
        file_counts: Dict[str, int] = {}
        for f in all_findings:
            if isinstance(f, dict):
                fp = f.get("file_path", f.get("file", ""))
                if fp:
                    file_counts[fp] = file_counts.get(fp, 0) + 1
        attention_points = [f"{fp} ({cnt} findings)" for fp, cnt in sorted(file_counts.items(), key=lambda x: -x[1])[:10]]

        # Priority areas from critical/high files
        priority_areas = [fp for fp, cnt in file_counts.items()
                         if any(isinstance(f, dict) and f.get("file_path", f.get("file", "")) == fp
                                and f.get("severity", "").lower() in ("critical", "high")
                                for f in all_findings)][:10]

        return HandoffPayload(
            summary=f"Analysis completed. {len(all_findings)} findings, {sev_counts.get('critical', 0)} critical.",
            key_findings=key_findings,
            insights=insights,
            suggested_actions=suggested_actions,
            attention_points=attention_points,
            priority_areas=priority_areas,
            context_data=ctx,
            confidence=analysis.confidence,
            from_agent="analysis",
            work_completed=list(analysis.work_completed) if analysis.work_completed else [analysis.summary],
        )

    def _build_reporting_handoff(self) -> Optional[HandoffPayload]:
        """Build handoff for Reporting phase from all results."""
        verification = self.get_handoff("verification")
        if not verification:
            return None

        return HandoffPayload(
            summary=verification.summary,
            key_findings=list(verification.key_findings),
            insights=list(verification.insights),
            suggested_actions=list(verification.suggested_actions),
            attention_points=list(verification.attention_points),
            priority_areas=list(verification.priority_areas),
            context_data=dict(verification.context_data),
            confidence=verification.confidence,
            from_agent="verification",
            work_completed=list(verification.work_completed) if verification.work_completed else [verification.summary],
        )
