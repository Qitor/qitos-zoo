"""AuditFlow — top-level orchestration of a DeepAudit security audit run."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from qitos.core.agent_spec import AgentRegistry, AgentSpec
from qitos.core.task import Task
from qitos.engine.engine import Engine
from qitos.engine.states import RuntimeBudget
from qitos.engine.stop_criteria import FinalResultCriteria

from ..agents.orchestrator import HandoffPayload
from ..agents.recon import ReconAgent
from ..agents.analysis import AnalysisAgent
from ..agents.verification import VerificationAgent
from ..agents._reduce_utils import normalize_finding
from ..config.defaults import DeepAuditConfig
from ..critic import (
    FilePathValidationCritic,
    RepeatedToolCallCritic,
    EmptyResponseCritic,
    AuditProgressCritic,
    GracefulShutdownCritic,
)
from ..knowledge.loader import knowledge_loader
from ..tools.barrier import ReconResult, AnalysisResult, VerificationResult, AuditDone
from ..tools.file_tools import (
    ReadFileTool, SmartScanTool, PatternMatchTool, CodeAnalysisTool,
    ExtractFunctionTool, QuickAuditTool, SearchCodeTool, ListFilesTool,
)
from ..tools.external_scanners import build_scanner_tools
from ..tools.dataflow import DataflowAnalysisTool
from ..tools.vuln_tools import VulnerabilityValidationTool, CreateVulnerabilityReportTool
from ..tools.sandbox_tools import RunCodeTool, SandboxExecTool, SandboxHttpTool
from ..tools.injection_tests import (
    TestCommandInjectionTool, TestSqlInjectionTool, TestXssTool,
    TestPathTraversalTool, TestSstiTool, TestDeserializationTool, VulnTestTool,
)
from ..tools.language_tests import (
    PhpTestTool, PythonTestTool, JavaScriptTestTool, JavaTestTool,
    GoTestTool, RubyTestTool, ShellTestTool, CodeTestTool,
)
from ..tools.knowledge_tools import (
    SecurityKnowledgeQueryTool, ListKnowledgeModulesTool, GetVulnerabilityKnowledgeTool,
)
from .phase_manager import PhaseManager


@dataclass
class AuditResult:
    """Result of a DeepAudit security audit run."""

    task: str
    report: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    handoffs: Dict[str, Any] = field(default_factory=dict)
    tech_stack: Dict[str, str] = field(default_factory=dict)
    total_steps: int = 0
    total_tokens: int = 0
    duration_seconds: float = 0.0
    status: str = "completed"
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class AuditFlow:
    """Top-level orchestration of a DeepAudit security audit run.

    Flow:
    1. _build_system() — create agents, register tools per agent
    2. _run_recon() → HandoffPayload
    3. _run_analysis(task, recon_handoff) → HandoffPayload
    4. _run_verification(task, analysis_handoff) → HandoffPayload
    5. _generate_report(all_handoffs) → report string
    6. Return AuditResult

    Phase 1 integrations:
    - Checkpoint: save state at each phase boundary
    - Tracing: structured span-based tracing per phase
    """

    def __init__(
        self,
        config: DeepAuditConfig,
        llm: Any = None,
        checkpoint_path: str | None = None,
        tracing_mode: str = "disabled",
    ):
        self.config = config
        self.llm = llm
        self.phase_manager = PhaseManager()
        self._all_findings: List[Dict[str, Any]] = []
        self.checkpoint_path = checkpoint_path
        self.tracing_mode = tracing_mode

    def run(self, task: str, target_path: Optional[str] = None) -> AuditResult:
        """Execute the full audit pipeline."""
        start_time = time.time()
        target = target_path or self.config.target_path

        result = AuditResult(task=task)

        try:
            # Phase 1: Recon
            recon_handoff = self._run_recon(task, target)
            if recon_handoff:
                self.phase_manager.complete_phase("recon", recon_handoff)
                result.handoffs["recon"] = recon_handoff
                result.tech_stack = recon_handoff.context_data.get("tech_stack", {})

            # Phase 2: Analysis
            analysis_handoff = self._run_analysis(task, target, recon_handoff)
            if analysis_handoff:
                self.phase_manager.complete_phase("analysis", analysis_handoff)
                result.handoffs["analysis"] = analysis_handoff
                for f in analysis_handoff.context_data.get("findings", []):
                    self._all_findings.append(f)

            # Phase 3: Verification
            verification_handoff = self._run_verification(task, target, analysis_handoff)
            if verification_handoff:
                self.phase_manager.complete_phase("verification", verification_handoff)
                result.handoffs["verification"] = verification_handoff
                for f in verification_handoff.context_data.get("verified_findings", []):
                    self._all_findings.append(f)

            # Generate report
            result.report = self._generate_report(result.handoffs)
            result.findings = self._normalize_and_dedup_findings(self._all_findings)

            # Count severities
            for f in result.findings:
                sev = f.get("severity", "medium").lower()
                if sev == "critical":
                    result.critical_count += 1
                elif sev == "high":
                    result.high_count += 1
                elif sev == "medium":
                    result.medium_count += 1
                else:
                    result.low_count += 1

        except Exception as e:
            import traceback
            result.status = "error"
            result.report = f"Audit failed with error: {e}\n{traceback.format_exc()}"

        result.duration_seconds = time.time() - start_time
        return result

    def _normalize_and_dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize and deduplicate findings from all phases.

        Normalizes field names, infers missing types, auto-generates titles,
        validates file paths, then deduplicates by (file_path, line, vulnerability_type)
        with smart merge (best title, verified verdict, combined evidence).
        """
        # Normalize
        normalized = []
        for f in findings:
            nf = normalize_finding(f, project_root=self.config.target_path)
            if nf is not None:
                normalized.append(nf)

        # Dedup by fingerprint
        deduped: Dict[tuple, Dict[str, Any]] = {}
        for f in normalized:
            fingerprint = (
                f.get("file_path", ""),
                f.get("line_start", f.get("line", 0)),
                f.get("vulnerability_type", "unknown"),
            )
            if fingerprint in deduped:
                existing = deduped[fingerprint]
                # Smart merge: keep best values
                if len(f.get("title", "")) > len(existing.get("title", "")):
                    existing["title"] = f["title"]
                if f.get("verdict") in ("confirmed", "likely") and existing.get("verdict") not in ("confirmed",):
                    existing["verdict"] = f["verdict"]
                if f.get("line_start", f.get("line", 0)) and not existing.get("line_start", existing.get("line", 0)):
                    existing["line_start"] = f.get("line_start", f.get("line", 0))
                if f.get("confidence", 0) > existing.get("confidence", 0):
                    existing["confidence"] = f["confidence"]
                # Combine evidence
                ev = existing.get("evidence", "")
                new_ev = f.get("evidence", "")
                if new_ev and new_ev not in ev:
                    existing["evidence"] = f"{ev}; {new_ev}" if ev else new_ev
                # Combine source agents
                src = existing.get("source_agent", "")
                new_src = f.get("source_agent", "")
                if new_src and new_src not in src:
                    existing["source_agent"] = f"{src}, {new_src}" if src else new_src
            else:
                deduped[fingerprint] = dict(f)

        # Filter out hallucinated paths
        return [f for f in deduped.values() if not f.get("_hallucinated_path")]

    def _run_recon(self, task: str, target_path: str) -> Optional[HandoffPayload]:
        """Execute the Recon phase."""
        agent = ReconAgent(llm=self.llm, target_path=target_path)

        # Inject framework knowledge to help identify tech stack
        from ..knowledge.loader import knowledge_loader
        framework_ctx = knowledge_loader.build_prompt_section(
            tech_stack={"framework": "all"}  # Load all framework knowledge for recon
        )
        agent._knowledge_context = framework_ctx

        tools = self._build_recon_tools()

        engine = self._create_engine(
            agent, tools, max_steps=self.config.max_steps_recon,
            barrier_tool_name="recon_result",
        )

        t = Task(id="recon", objective=task)
        engine_result = engine.run(t)

        return self._extract_handoff(engine_result, "recon")

    def _run_analysis(self, task: str, target_path: str, recon_handoff: Optional[HandoffPayload]) -> Optional[HandoffPayload]:
        """Execute the Analysis phase."""
        agent = AnalysisAgent(llm=self.llm, target_path=target_path)

        # Inject recon handoff as context
        if recon_handoff:
            agent._handoff = recon_handoff

            # Inject knowledge context based on tech stack
            tech_stack = recon_handoff.context_data.get("tech_stack", {})
            knowledge_ctx = knowledge_loader.build_prompt_section(tech_stack=tech_stack)
            agent._knowledge_context = knowledge_ctx

        tools = self._build_analysis_tools()

        engine = self._create_engine(
            agent, tools, max_steps=self.config.max_steps_analysis,
            barrier_tool_name="analysis_result",
        )

        t = Task(id="analysis", objective=task)
        engine_result = engine.run(t)

        return self._extract_handoff(engine_result, "analysis")

    def _run_verification(self, task: str, target_path: str, analysis_handoff: Optional[HandoffPayload]) -> Optional[HandoffPayload]:
        """Execute the Verification phase."""
        agent = VerificationAgent(llm=self.llm, target_path=target_path)

        # Inject analysis handoff as context
        if analysis_handoff:
            agent._handoff = analysis_handoff

            # Also inject recon context if available
            recon_handoff = self.phase_manager.get_handoff("recon")
            if recon_handoff:
                agent._execution_context = f"Tech Stack: {recon_handoff.context_data.get('tech_stack', {})}"

                # Inject vulnerability knowledge matching findings from Analysis
                findings = analysis_handoff.context_data.get("findings", [])
                vuln_types = set()
                for f in findings:
                    if isinstance(f, dict):
                        vt = f.get("vulnerability_type", "")
                        if vt:
                            vuln_types.add(vt)
                if vuln_types:
                    from ..knowledge.loader import knowledge_loader
                    knowledge_ctx = knowledge_loader.build_prompt_section(
                        tech_stack=recon_handoff.context_data.get("tech_stack", {})
                    )
                    agent._knowledge_context = knowledge_ctx

        tools = self._build_verification_tools()

        engine = self._create_engine(
            agent, tools, max_steps=self.config.max_steps_verification,
            barrier_tool_name="verification_result",
        )

        t = Task(id="verification", objective=task)
        engine_result = engine.run(t)

        return self._extract_handoff(engine_result, "verification")

    def _create_engine(
        self,
        agent: Any,
        tools: List[Any],
        max_steps: int,
        barrier_tool_name: str,
    ) -> Engine:
        """Create an Engine with critics and recovery policy."""
        # Register tools on the agent's tool_registry
        from qitos.core.tool_registry import ToolRegistry
        registry = ToolRegistry()
        for tool in tools:
            registry.register(tool)

        # Set the tool registry on the agent so Engine picks it up
        agent.tool_registry = registry

        # Resolve protocol from LLM harness metadata so tool_schema_delivery
        # (e.g. "api_parameter") and native_tool_call_preferred are honored.
        # Without this, Engine.resolve_protocol() falls back to model-name
        # inference and uses the protocol's default delivery ("hybrid"),
        # bypassing the preset override.
        protocol = self._resolve_protocol_from_harness()

        # Build critics
        critics = [
            FilePathValidationCritic(project_root=self.config.target_path),
            RepeatedToolCallCritic(max_repeats=2),
            EmptyResponseCritic(max_retries=3),
            AuditProgressCritic(stagnation_threshold=5),
            GracefulShutdownCritic(barrier_tool_name=barrier_tool_name, steps_remaining_threshold=3),
        ]

        budget = RuntimeBudget(max_steps=max_steps)

        # Checkpoint store (Phase 1 integration)
        checkpoint_store = None
        if self.checkpoint_path:
            from qitos.checkpoint.sqlite_store import SqliteCheckpointStore
            checkpoint_store = SqliteCheckpointStore(self.checkpoint_path)

        # Tracing provider (Phase 1 integration)
        tracing_provider = None
        if self.tracing_mode != "disabled":
            from qitos.tracing import TracingProvider, TracingMode
            from qitos.tracing.json_processor import JsonFileTraceProcessor
            import os
            mode = TracingMode.ENABLED_WITHOUT_DATA if self.tracing_mode == "without_data" else TracingMode.ENABLED
            trace_dir = os.path.join(
                self.config.target_path, ".qitos", "traces", "audit"
            )
            tracing_provider = TracingProvider(
                processors=[JsonFileTraceProcessor(output_dir=trace_dir)],
                mode=mode,
            )

        return Engine(
            agent=agent,
            critics=critics,
            budget=budget,
            protocol=protocol,
            checkpoint_store=checkpoint_store,
            tracing_provider=tracing_provider,
        )

    def _resolve_protocol_from_harness(self) -> Any:
        """Resolve protocol from LLM harness metadata.

        Uses the harness preset system to build a protocol with the correct
        tool_schema_delivery (e.g. "api_parameter") and other overrides,
        rather than falling back to the protocol's defaults.
        """
        if self.llm is None:
            return None
        metadata = dict(getattr(self.llm, "qitos_harness_metadata", {}) or {})
        if metadata:
            model_name = getattr(self.llm, "model", None) or getattr(self.llm, "model_name", None)
            if model_name:
                try:
                    from qitos.harness import build_harness_policy
                    policy = build_harness_policy(model_name=model_name)
                    protocol = getattr(policy, "protocol", None)
                    if protocol is not None:
                        return protocol
                except Exception:
                    pass
        return None

    def _extract_handoff(self, engine_result: Any, phase: str) -> Optional[HandoffPayload]:
        """Extract HandoffPayload from engine result."""
        # The engine result may contain the handoff in various places
        if hasattr(engine_result, "state"):
            state = engine_result.state
            if hasattr(state, "handoff") and state.handoff:
                if isinstance(state.handoff, dict):
                    # Ensure context_data is a dict (models sometimes return it as a string)
                    handoff_data = dict(state.handoff)
                    for key in ("context_data", "key_findings", "insights",
                                "suggested_actions", "attention_points", "priority_areas"):
                        val = handoff_data.get(key)
                        if isinstance(val, str):
                            try:
                                handoff_data[key] = json.loads(val)
                            except (json.JSONDecodeError, TypeError):
                                if key == "context_data":
                                    handoff_data[key] = {"raw": val}
                                else:
                                    handoff_data[key] = [val]
                    return HandoffPayload(**{k: v for k, v in handoff_data.items()
                                            if k in HandoffPayload.__dataclass_fields__})
                return state.handoff

        # Try to extract from final action results
        if hasattr(engine_result, "final_action"):
            action = engine_result.final_action
            if hasattr(action, "output") and isinstance(action.output, dict):
                output = action.output
                if output.get("phase") == phase:
                    return HandoffPayload(**{k: v for k, v in output.items()
                                            if k in HandoffPayload.__dataclass_fields__})

        return None

    # ── Tool builders ────────────────────────────────────────────

    def _build_recon_tools(self) -> List[Any]:
        """Build tools for the Recon agent."""
        tools = [
            ReconResult(),
            ReadFileTool(),
            ListFilesTool(),
            SearchCodeTool(),
            SmartScanTool(),
            PatternMatchTool(),
            CodeAnalysisTool(),
            SecurityKnowledgeQueryTool(),
            ListKnowledgeModulesTool(),
        ]
        # Add external scanners (quick scan during recon)
        tools.extend(build_scanner_tools(self.config)[:3])  # semgrep, bandit, gitleaks
        return tools

    def _build_analysis_tools(self) -> List[Any]:
        """Build tools for the Analysis agent."""
        tools = [
            AnalysisResult(),
            ReadFileTool(),
            SearchCodeTool(),
            SmartScanTool(),
            PatternMatchTool(),
            CodeAnalysisTool(),
            DataflowAnalysisTool(),
            ExtractFunctionTool(),
            QuickAuditTool(),
            CreateVulnerabilityReportTool(),
            SecurityKnowledgeQueryTool(),
            GetVulnerabilityKnowledgeTool(),
        ]
        # All external scanners
        tools.extend(build_scanner_tools(self.config))
        return tools

    def _build_verification_tools(self) -> List[Any]:
        """Build tools for the Verification agent."""
        tools = [
            VerificationResult(),
            VulnerabilityValidationTool(),
            ReadFileTool(),
            RunCodeTool(),
            SandboxExecTool(),
            SandboxHttpTool(),
            # Injection tests
            TestCommandInjectionTool(),
            TestSqlInjectionTool(),
            TestXssTool(),
            TestPathTraversalTool(),
            TestSstiTool(),
            TestDeserializationTool(),
            VulnTestTool(),
            # Language tests
            PhpTestTool(),
            PythonTestTool(),
            JavaScriptTestTool(),
            JavaTestTool(),
            GoTestTool(),
            RubyTestTool(),
            ShellTestTool(),
            CodeTestTool(),
        ]
        return tools

    def _generate_report(self, handoffs: Dict[str, Any]) -> str:
        """Generate a final audit report from all handoff data."""
        fmt = self.config.report_format
        if fmt == "json":
            return self._generate_json_report(handoffs)
        elif fmt == "sarif":
            return self._generate_sarif_report(handoffs)
        else:
            return self._generate_markdown_report(handoffs)

    def _generate_markdown_report(self, handoffs: Dict[str, Any]) -> str:
        """Generate a Markdown format audit report."""
        sections = []
        sections.append("# DeepAudit Security Audit Report\n")

        # Executive summary
        sections.append("## Executive Summary\n")
        total_findings = len(self._all_findings)
        critical = sum(1 for f in self._all_findings if f.get("severity") == "critical")
        high = sum(1 for f in self._all_findings if f.get("severity") == "high")
        sections.append(f"- Total findings: {total_findings}")
        sections.append(f"- Critical: {critical}")
        sections.append(f"- High: {high}")
        sections.append("")

        # Tech stack
        recon = handoffs.get("recon")
        if recon and isinstance(recon, HandoffPayload):
            sections.append("## Technology Stack\n")
            tech = recon.context_data.get("tech_stack", {})
            for k, v in tech.items():
                sections.append(f"- **{k}**: {v}")
            sections.append("")

        # Findings
        if self._all_findings:
            sections.append("## Findings\n")
            for i, f in enumerate(self._all_findings, 1):
                severity = f.get("severity", "medium").upper()
                verdict = f.get("verdict", "uncertain")
                title = f.get("title", f.get("vulnerability_type", "Unknown"))
                file_path = f.get("file_path", f.get("file", ""))
                line = f.get("line", f.get("line_start", 0))
                sections.append(f"### {i}. [{severity}] {title}")
                if file_path:
                    sections.append(f"- **File**: {file_path}" + (f":{line}" if line else ""))
                if f.get("evidence"):
                    sections.append(f"- **Evidence**: {f['evidence'][:200]}")
                if f.get("recommendation") or f.get("suggestion"):
                    sections.append(f"- **Recommendation**: {f.get('recommendation', f.get('suggestion', ''))[:200]}")
                sections.append(f"- **Verdict**: {verdict}")
                sections.append(f"- **Confidence**: {f.get('confidence', 0.5):.0%}")
                sections.append("")

        # Phase summaries
        for phase in ["recon", "analysis", "verification"]:
            h = handoffs.get(phase)
            if h:
                if isinstance(h, HandoffPayload):
                    sections.append(f"## {phase.title()} Phase Summary\n")
                    sections.append(h.summary)
                    sections.append("")

        return "\n".join(sections)

    def _generate_json_report(self, handoffs: Dict[str, Any]) -> str:
        """Generate a JSON format audit report."""
        report_data = {
            "schema": "deepaudit-report-v1",
            "target_path": self.config.target_path,
            "summary": {
                "total_findings": len(self._all_findings),
                "critical": sum(1 for f in self._all_findings if f.get("severity") == "critical"),
                "high": sum(1 for f in self._all_findings if f.get("severity") == "high"),
                "medium": sum(1 for f in self._all_findings if f.get("severity") == "medium"),
                "low": sum(1 for f in self._all_findings if f.get("severity") == "low"),
                "info": sum(1 for f in self._all_findings if f.get("severity") == "info"),
            },
            "tech_stack": {},
            "findings": self._all_findings,
            "phases": {},
        }

        recon = handoffs.get("recon")
        if recon and isinstance(recon, HandoffPayload):
            report_data["tech_stack"] = recon.context_data.get("tech_stack", {})

        for phase in ["recon", "analysis", "verification"]:
            h = handoffs.get(phase)
            if h and isinstance(h, HandoffPayload):
                report_data["phases"][phase] = {
                    "summary": h.summary,
                    "confidence": h.confidence,
                    "from_agent": h.from_agent,
                }

        return json.dumps(report_data, indent=2, default=str)

    def _generate_sarif_report(self, handoffs: Dict[str, Any]) -> str:
        """Generate a SARIF 2.1.0 format audit report."""
        # Build rules from findings
        rules = []
        results = []
        seen_rule_ids: Dict[str, int] = {}

        for f in self._all_findings:
            vuln_type = f.get("vulnerability_type", "unknown")
            rule_id = f"DA-{vuln_type.upper().replace('_', '-')}"
            if rule_id not in seen_rule_ids:
                seen_rule_ids[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": vuln_type,
                    "shortDescription": {"text": f.get("title", vuln_type)},
                    "properties": {
                        "tags": ["security", f"vulnerability-type:{vuln_type}"],
                    },
                })

            severity = f.get("severity", "medium")
            sarif_level = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "note",
            }.get(severity, "warning")

            file_path = f.get("file_path", f.get("file", ""))
            line_start = f.get("line_start", f.get("line", 0))

            result_entry = {
                "ruleId": rule_id,
                "ruleIndex": seen_rule_ids[rule_id],
                "level": sarif_level,
                "message": {"text": f.get("title", vuln_type)},
            }

            if file_path:
                result_entry["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": line_start} if line_start else {},
                    }
                }]

            results.append(result_entry)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DeepAudit",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/qitos/deepaudit",
                        "rules": rules,
                    }
                },
                "results": results,
            }]
        }

        return json.dumps(sarif, indent=2, default=str)
