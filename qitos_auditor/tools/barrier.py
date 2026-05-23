"""Barrier tools — signal agent phase completion and deliver results.

Each agent type has its own barrier tool that signals completion
and delivers the agent's structured result as a HandoffPayload.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


# ── HandoffPayload helper ──────────────────────────────────────────────

def _build_handoff_payload(args: Dict[str, Any]) -> Dict[str, Any]:
    """Build a HandoffPayload dict from tool arguments.

    Expected args: summary, key_findings, insights, suggested_actions,
    attention_points, priority_areas, context_data, confidence.
    """
    return {
        "summary": str(args.get("summary", "")),
        "key_findings": args.get("key_findings", []),
        "insights": args.get("insights", []),
        "suggested_actions": args.get("suggested_actions", []),
        "attention_points": args.get("attention_points", []),
        "priority_areas": args.get("priority_areas", []),
        "context_data": args.get("context_data", {}),
        "confidence": float(args.get("confidence", 0.5)),
    }


# ── Barrier tools ──────────────────────────────────────────────────────

class AuditDone(BaseTool):
    """Signal that the entire audit is complete with a final report."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="done",
                description="Signal that the audit is complete. "
                "MUST be called when all phases are done. "
                "Provide a final audit summary.",
                parameters={
                    "summary": {
                        "type": "string",
                        "description": "Final audit summary covering all phases and key findings",
                    },
                    "findings_count": {
                        "type": "integer",
                        "description": "Total number of findings across all phases",
                    },
                    "critical_count": {
                        "type": "integer",
                        "description": "Number of critical severity findings",
                    },
                },
                required=["summary"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return {
            "status": "done",
            "summary": str(args.get("summary", "")),
            "findings_count": int(args.get("findings_count", 0)),
            "critical_count": int(args.get("critical_count", 0)),
        }


class ReconResult(BaseTool):
    """Deliver reconnaissance results with a HandoffPayload.

    Called by ReconAgent when it has completed scanning the project
    structure and identifying tech stack, entry points, and risks.
    """

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="recon_result",
                description="Deliver reconnaissance results. Call when you have completed "
                "project scanning. You MUST provide all HandoffPayload fields: "
                "summary, key_findings, insights, suggested_actions, "
                "attention_points, priority_areas, context_data, confidence.",
                parameters={
                    "summary": {
                        "type": "string",
                        "description": "Concise summary of the reconnaissance phase (max 200 words)",
                    },
                    "key_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of critical discoveries about the project",
                    },
                    "insights": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Strategic observations for the analysis phase",
                    },
                    "suggested_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Recommended next steps for the analysis agent",
                    },
                    "attention_points": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Areas requiring special focus during analysis",
                    },
                    "priority_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "High-priority files or directories for analysis",
                    },
                    "context_data": {
                        "type": "object",
                        "description": "Structured data: tech_stack, entry_points, file_inventory, dependencies",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Overall confidence in recon results (0.0-1.0)",
                    },
                },
                required=["summary", "key_findings", "suggested_actions", "context_data", "confidence"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        payload = _build_handoff_payload(args)
        payload["phase"] = "recon"
        return payload


class AnalysisResult(BaseTool):
    """Deliver analysis results with a HandoffPayload.

    Called by AnalysisAgent when it has completed vulnerability detection.
    """

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="analysis_result",
                description="Deliver vulnerability analysis results. Call when you have completed "
                "vulnerability detection. You MUST provide all HandoffPayload fields: "
                "summary, key_findings, insights, suggested_actions, "
                "attention_points, priority_areas, context_data, confidence.",
                parameters={
                    "summary": {
                        "type": "string",
                        "description": "Concise summary of the analysis phase (max 200 words)",
                    },
                    "key_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of discovered vulnerabilities with severity",
                    },
                    "insights": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Strategic observations for the verification phase",
                    },
                    "suggested_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Recommended verification strategies for each finding",
                    },
                    "attention_points": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Findings that need priority verification",
                    },
                    "priority_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "High-priority findings for verification",
                    },
                    "context_data": {
                        "type": "object",
                        "description": "Structured data: findings list, scanner_results, analyzed_files",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Overall confidence in analysis results (0.0-1.0)",
                    },
                },
                required=["summary", "key_findings", "suggested_actions", "context_data", "confidence"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        payload = _build_handoff_payload(args)
        payload["phase"] = "analysis"
        return payload


class VerificationResult(BaseTool):
    """Deliver verification results with a HandoffPayload.

    Called by VerificationAgent when it has completed validating findings.
    """

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="verification_result",
                description="Deliver verification results. Call when you have completed "
                "validating findings. You MUST provide all HandoffPayload fields: "
                "summary, key_findings, insights, suggested_actions, "
                "attention_points, priority_areas, context_data, confidence.",
                parameters={
                    "summary": {
                        "type": "string",
                        "description": "Concise summary of the verification phase (max 200 words)",
                    },
                    "key_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of verified findings with verdicts",
                    },
                    "insights": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Observations about false positive patterns or verification challenges",
                    },
                    "suggested_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Recommended remediation actions for confirmed findings",
                    },
                    "attention_points": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Uncertain findings that may need manual review",
                    },
                    "priority_areas": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Confirmed findings that need immediate attention",
                    },
                    "context_data": {
                        "type": "object",
                        "description": "Structured data: verified_findings, poc_results, verdict_summary",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Overall confidence in verification results (0.0-1.0)",
                    },
                },
                required=["summary", "key_findings", "suggested_actions", "context_data", "confidence"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        payload = _build_handoff_payload(args)
        payload["phase"] = "verification"
        return payload
