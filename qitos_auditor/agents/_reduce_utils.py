"""Shared utilities for agent reduce() methods."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def extract_tool_results(observation: Any) -> Dict[str, Any]:
    """Extract tool name -> output mapping from observation.

    The engine wraps tool execution results as ToolResult objects
    (with .output attribute) or dicts. This helper normalizes them
    into a dict keyed by tool name or output type.
    """
    results: Dict[str, Any] = {}
    action_results = []
    if hasattr(observation, "action_results"):
        action_results = list(observation.action_results or [])
    elif isinstance(observation, dict):
        action_results = list(observation.get("action_results", []))
    for ar in action_results:
        output = getattr(ar, "output", None)
        if output is None and isinstance(ar, dict):
            output = ar.get("output", ar)
        # Try to get tool_name from metadata first (engine stores it there)
        metadata = getattr(ar, "metadata", None) or {}
        name = ""
        if isinstance(metadata, dict):
            name = metadata.get("tool_name", "")
        # Fallback: check output dict for name/type keys
        if not name and isinstance(output, dict):
            name = output.get("name", output.get("type", ""))
        if isinstance(output, dict):
            if name:
                results[name] = output
            else:
                results[f"tool_{len(results)}"] = output
    return results


def inject_execution_context(agent: Any, prompt: str) -> str:
    """Append execution context XML to a system prompt if available on the agent.

    Used by specialist agents (recon, analysis, verification) to receive
    awareness of the global task and handoff context from previous phases.
    """
    ctx = getattr(agent, '_execution_context', '')
    if ctx:
        prompt += f"\n\n# Execution Context\n{ctx}"
    return prompt


def inject_handoff_context(agent: Any, prompt: str) -> str:
    """Append handoff payload from previous agent phase to the system prompt."""
    handoff = getattr(agent, '_handoff', None)
    if handoff is not None:
        from ..agents.orchestrator import HandoffPayload
        if isinstance(handoff, HandoffPayload):
            prompt += f"\n\n# Previous Phase Handoff\n{handoff.to_prompt_context()}"
    return prompt


def inject_knowledge_context(agent: Any, prompt: str) -> str:
    """Append knowledge module context to the system prompt."""
    knowledge_ctx = getattr(agent, '_knowledge_context', '')
    if knowledge_ctx:
        prompt += f"\n\n# Security Knowledge\n{knowledge_ctx}"
    return prompt


def parse_finding_from_tool_output(output: Any) -> Optional[Dict[str, Any]]:
    """Try to parse a FindingEntry-like dict from a tool output.

    Tools like create_vulnerability_report return structured finding data.
    This helper extracts it regardless of whether it's a dict, JSON string,
    or nested in a larger result object.
    """
    import json

    if isinstance(output, dict):
        if "title" in output and ("file" in output or "file_path" in output):
            return output
        if "finding" in output:
            return parse_finding_from_tool_output(output["finding"])
    if isinstance(output, str):
        try:
            data = json.loads(output)
            return parse_finding_from_tool_output(data)
        except (json.JSONDecodeError, TypeError):
            pass
    return None


# ── Finding normalization ───────────────────────────────────────────

# Field name aliases: DeepAudit agents may return findings with different field names
_FIELD_ALIASES = {
    "location": "file_path",   # "app.py:42" → split into file_path + line_start
    "file": "file_path",
    "path": "file_path",
    "type": "vulnerability_type",
    "risk": "severity",
    "code": "code_snippet",
    "recommendation": "suggestion",
    "line": "line_start",
    "impact": None,            # append to description
}

# Keywords for inferring vulnerability_type from description text
_VULN_TYPE_KEYWORDS = {
    "command_injection": ["command injection", "os.system", "subprocess", "shell=True", "rce", "cmd injection"],
    "sql_injection": ["sql injection", "sqli", "sql inject", "sql query", "cursor.execute"],
    "xss": ["xss", "cross-site scripting", "innerHTML", "document.write", "reflected xss", "stored xss"],
    "path_traversal": ["path traversal", "lfi", "directory traversal", "../", "file inclusion"],
    "ssrf": ["ssrf", "server-side request", "request forgery"],
    "ssti": ["ssti", "template injection", "render_template_string", "jinja2"],
    "deserialization": ["deserialization", "pickle", "unserialize", "yaml.load", "objectinputstream"],
    "hardcoded_secrets": ["hardcoded", "secret", "api key", "password", "credential leak"],
    "auth_bypass": ["auth bypass", "authentication bypass", "idor", "access control"],
    "xxe": ["xxe", "xml external entity", "xml injection"],
    "csrf": ["csrf", "cross-site request"],
}


def normalize_finding(finding: Dict[str, Any], project_root: str = "") -> Optional[Dict[str, Any]]:
    """Normalize a finding dict to a canonical field schema.

    Maps alternate field names, infers missing vulnerability_type from
    description text, auto-generates titles, and validates file paths.
    Returns None if the finding references a nonexistent file (hallucination).
    """
    import os
    import re

    if not isinstance(finding, dict):
        return None

    result = dict(finding)

    # 1. Field name mapping
    for old_key, new_key in _FIELD_ALIASES.items():
        if old_key in result and new_key:
            if new_key not in result or not result[new_key]:
                result[new_key] = result[old_key]
        if old_key == "location" and "location" in result:
            # "app.py:42" → file_path + line_start
            loc = str(result.pop("location"))
            if ":" in loc:
                parts = loc.rsplit(":", 1)
                if "file_path" not in result or not result["file_path"]:
                    result["file_path"] = parts[0]
                try:
                    result.setdefault("line_start", int(parts[1]))
                except ValueError:
                    pass
            elif "file_path" not in result or not result["file_path"]:
                result["file_path"] = loc
        if old_key == "impact" and "impact" in result:
            impact_val = result.pop("impact", "")
            if impact_val and "description" in result:
                result["description"] = f"{result['description']}. Impact: {impact_val}"

    # 2. Infer vulnerability_type from description
    if not result.get("vulnerability_type") or result["vulnerability_type"] in ("Vulnerability", "vulnerability", "Other"):
        desc = f"{result.get('description', '')} {result.get('title', '')}".lower()
        for vtype, keywords in _VULN_TYPE_KEYWORDS.items():
            if any(kw in desc for kw in keywords):
                result["vulnerability_type"] = vtype
                break
        else:
            if not result.get("vulnerability_type"):
                result["vulnerability_type"] = "unknown"

    # 3. Auto-generate title if missing
    if not result.get("title"):
        vtype = result.get("vulnerability_type", "issue")
        fpath = result.get("file_path", "")
        basename = os.path.basename(fpath) if fpath else "unknown file"
        result["title"] = f"{vtype.replace('_', ' ').title()} in {basename}"

    # 4. File path validation (anti-hallucination)
    file_path = result.get("file_path", "")
    if file_path and project_root:
        full = os.path.join(project_root, file_path)
        if not os.path.exists(full):
            # Check if it's a hallucinated path
            result["verdict"] = "false_positive"
            result["_hallucinated_path"] = True

    return result
