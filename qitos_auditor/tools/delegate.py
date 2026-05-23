"""Delegate tool builder — creates tools that allow the Orchestrator to dispatch sub-agents."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


class DelegateToReconTool(BaseTool):
    """Delegate to the Recon specialist agent."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="delegate_to_recon",
                description="Delegate the reconnaissance phase to the Recon specialist agent. "
                "The Recon agent scans project structure, identifies tech stack, "
                "discovers entry points, and recommends security tools.",
                parameters={
                    "task_description": {
                        "type": "string",
                        "description": "Description of what the recon agent should focus on",
                    },
                    "target_path": {
                        "type": "string",
                        "description": "Path to the codebase to audit",
                    },
                    "focus_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific areas to focus on (optional)",
                    },
                },
                required=["task_description"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "action": "delegate",
            "agent": "recon",
            "task_description": args.get("task_description", ""),
            "target_path": args.get("target_path", ""),
            "focus_areas": args.get("focus_areas", []),
            "status": "dispatched",
        }


class DelegateToAnalysisTool(BaseTool):
    """Delegate to the Analysis specialist agent."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="delegate_to_analysis",
                description="Delegate the vulnerability analysis phase to the Analysis specialist agent. "
                "The Analysis agent runs external scanners, performs deep code analysis, "
                "and identifies vulnerabilities with evidence.",
                parameters={
                    "task_description": {
                        "type": "string",
                        "description": "Description of what the analysis agent should focus on",
                    },
                    "target_path": {
                        "type": "string",
                        "description": "Path to the codebase to audit",
                    },
                    "recon_summary": {
                        "type": "string",
                        "description": "Summary from the recon phase for context",
                    },
                    "priority_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "High-priority files/directories from recon (optional)",
                    },
                },
                required=["task_description"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "action": "delegate",
            "agent": "analysis",
            "task_description": args.get("task_description", ""),
            "target_path": args.get("target_path", ""),
            "recon_summary": args.get("recon_summary", ""),
            "priority_areas": args.get("priority_areas", []),
            "status": "dispatched",
        }


class DelegateToVerificationTool(BaseTool):
    """Delegate to the Verification specialist agent."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="delegate_to_verification",
                description="Delegate the verification phase to the Verification specialist agent. "
                "The Verification agent validates findings via PoC testing, assigns "
                "verdicts, and generates repair recommendations.",
                parameters={
                    "task_description": {
                        "type": "string",
                        "description": "Description of what the verification agent should focus on",
                    },
                    "target_path": {
                        "type": "string",
                        "description": "Path to the codebase to audit",
                    },
                    "findings_summary": {
                        "type": "string",
                        "description": "Summary of findings from the analysis phase",
                    },
                    "critical_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Critical/high findings requiring priority verification",
                    },
                },
                required=["task_description"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "action": "delegate",
            "agent": "verification",
            "task_description": args.get("task_description", ""),
            "target_path": args.get("target_path", ""),
            "findings_summary": args.get("findings_summary", ""),
            "critical_findings": args.get("critical_findings", []),
            "status": "dispatched",
        }


def build_audit_delegate_tools() -> List[BaseTool]:
    """Build all delegate tools for the Orchestrator agent."""
    return [
        DelegateToReconTool(),
        DelegateToAnalysisTool(),
        DelegateToVerificationTool(),
    ]
