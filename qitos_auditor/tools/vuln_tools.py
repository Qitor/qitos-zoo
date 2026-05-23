"""Vulnerability validation and reporting tools."""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


# ── Vulnerability validation ─────────────────────────────────────

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
VERDICTS = ["confirmed", "likely", "uncertain", "false_positive"]

_VULN_RECOMMENDATIONS = {
    "command_injection": "Use subprocess with shell=False and parameterized arguments. Never pass user input to os.system() or shell=True.",
    "sql_injection": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
    "xss": "Use context-aware output encoding. Apply HTML/entity escaping for HTML contexts, JavaScript escaping for JS contexts. Use Content-Security-Policy headers.",
    "path_traversal": "Validate and canonicalize file paths. Use os.path.realpath() and check that the resolved path stays within the allowed directory.",
    "ssrf": "Validate and whitelist allowed URLs/domains. Block requests to internal/private IP ranges. Use network-level egress filtering.",
    "deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON). If Pickle is required, use RestrictedUnpickler.",
    "auth_bypass": "Enforce authentication on all sensitive endpoints. Use a proven auth framework. Never rely on client-side checks.",
    "hardcoded_secret": "Move secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
    "hardcoded_credentials": "Move credentials to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
    "weak_crypto": "Use strong, modern algorithms (AES-256-GCM, RSA-2048+, SHA-256+). Avoid MD5, SHA1, DES, RC4.",
    "idor": "Validate object-level authorization on every access. Check that the requesting user owns or has access to the requested resource.",
    "xxe": "Disable external entity processing. Use defusedxml for Python. Configure XML parsers to disallow DTDs and external entities.",
    "ssti": "Use a sandboxed template engine. Never render user-controlled strings as templates. Use Jinja2's sandbox mode.",
    "csrf": "Implement anti-CSRF tokens on all state-changing requests. Use SameSite cookie attribute. Verify Origin/Referer headers.",
    "race_condition": "Use proper locking (database transactions, mutex). Implement idempotency keys for critical operations.",
    "open_redirect": "Whitelist allowed redirect destinations. Validate URL scheme and host. Never redirect to user-supplied URLs without validation.",
}


def _get_recommendation(vulnerability_type: str) -> str:
    """Get default remediation recommendation for a vulnerability type."""
    vt = vulnerability_type.lower().strip()
    return _VULN_RECOMMENDATIONS.get(vt, "Review and remediate based on the specific vulnerability pattern.")


class VulnerabilityValidationTool(BaseTool):
    """Validate a reported vulnerability with evidence and optional LLM deep analysis."""

    _LLM_PROMPT = """\
You are a security vulnerability validation expert. Analyze the following finding and determine if it is a real vulnerability.

## Finding
- Title: {title}
- File: {file_path}:{line_number}
- Type: {vulnerability_type}
- Severity: {severity}
- Data flow: {data_flow}
- Agent verdict: {verdict}
- Agent confidence: {confidence}

## Code
```
{code}
```

## Surrounding Context
```
{context}
```

Analyze whether the data flow from source to sink is real and exploitable. Consider:
1. Is user input actually reachable at the source?
2. Are there sanitizers or validators in the path?
3. Can the sink actually be exploited?
4. Is this a common pattern with known mitigations?

Respond in this EXACT JSON format (no markdown, no explanation outside the JSON):
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "verdict": "confirmed|likely|uncertain|false_positive",
  "exploitation_conditions": "What conditions must be met for exploitation",
  "attack_vector": "How an attacker would exploit this",
  "poc_idea": "Brief proof-of-concept approach",
  "false_positive_reason": "Why this might be a false positive (empty string if truly vulnerable)",
  "detailed_analysis": "Your detailed reasoning"
}}"""

    def __init__(self, llm=None):
        self._llm = llm
        super().__init__(
            ToolSpec(
                name="vulnerability_validation",
                description="Validate a reported vulnerability by checking file existence, "
                "code evidence, and data flow. When code and context are provided, "
                "uses LLM for deep analysis if available. You MUST validate before "
                "confirming any finding.",
                parameters={
                    "title": {
                        "type": "string",
                        "description": "Vulnerability title",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "File where vulnerability was found",
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "Line number of the vulnerability",
                    },
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Type of vulnerability (e.g., sql_injection, xss, command_injection)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity: critical, high, medium, low, info",
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Code snippet or evidence supporting the finding",
                    },
                    "data_flow": {
                        "type": "string",
                        "description": "Description of how user input reaches the dangerous sink",
                    },
                    "verdict": {
                        "type": "string",
                        "description": "Your assessment: confirmed, likely, uncertain, false_positive",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence score 0.0-1.0",
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "Recommended fix or mitigation",
                    },
                    "code": {
                        "type": "string",
                        "description": "The exact vulnerable code snippet from read_file output",
                    },
                    "context": {
                        "type": "string",
                        "description": "Surrounding code context (functions, imports, call sites)",
                    },
                },
                required=["title", "file_path", "vulnerability_type", "verdict"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        import os

        file_path = args.get("file_path", "")
        verdict = args.get("verdict", "uncertain")
        confidence = float(args.get("confidence", 0.5))

        # Validate file existence
        full_path = os.path.join(project_root, file_path)
        file_exists = os.path.exists(full_path)

        # Auto-correct verdict if file doesn't exist
        if not file_exists and verdict in ("confirmed", "likely"):
            verdict = "false_positive"
            confidence = min(confidence, 0.1)

        # Validate severity
        severity = args.get("severity", "medium").lower()
        if severity not in SEVERITY_LEVELS:
            severity = "medium"

        # Validate verdict
        if verdict not in VERDICTS:
            verdict = "uncertain"

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        # Infer confidence from verdict if not explicitly provided
        if "confidence" not in args:
            confidence_map = {
                "confirmed": 0.9,
                "likely": 0.65,
                "uncertain": 0.35,
                "false_positive": 0.1,
            }
            confidence = confidence_map.get(verdict, 0.5)

        finding_id = str(uuid.uuid4())[:8]

        result = {
            "id": finding_id,
            "title": args.get("title", ""),
            "file_path": file_path,
            "line": int(args.get("line_number", 0)),
            "vulnerability_type": args.get("vulnerability_type", ""),
            "severity": severity,
            "verdict": verdict,
            "confidence": confidence,
            "evidence": args.get("evidence", ""),
            "data_flow": args.get("data_flow", ""),
            "recommendation": args.get("recommendation", ""),
            "file_exists": file_exists,
            "cwe_id": args.get("cwe_id", ""),
            "validation_method": "rule_based",
        }

        # LLM deep analysis when code is provided and LLM is available
        code = args.get("code", "")
        context = args.get("context", "")
        if self._llm and (code or context):
            llm_result = self._llm_validate(
                title=args.get("title", ""),
                file_path=file_path,
                line_number=int(args.get("line_number", 0)),
                vulnerability_type=args.get("vulnerability_type", ""),
                severity=severity,
                data_flow=args.get("data_flow", ""),
                verdict=verdict,
                confidence=confidence,
                code=code,
                context=context,
            )
            if llm_result:
                # LLM result overrides verdict/confidence only when it has
                # stronger evidence (e.g., LLM says false_positive when file
                # exists but code doesn't match)
                result.update({
                    "verdict": llm_result.get("verdict", verdict),
                    "confidence": float(llm_result.get("confidence", confidence)),
                    "is_vulnerable": llm_result.get("is_vulnerable", None),
                    "exploitation_conditions": llm_result.get("exploitation_conditions", ""),
                    "attack_vector": llm_result.get("attack_vector", ""),
                    "poc_idea": llm_result.get("poc_idea", ""),
                    "false_positive_reason": llm_result.get("false_positive_reason", ""),
                    "detailed_analysis": llm_result.get("detailed_analysis", ""),
                    "validation_method": "llm_deep",
                })

        return result

    def _llm_validate(self, **kwargs) -> Optional[Dict[str, Any]]:
        """Use LLM to perform deep vulnerability validation."""
        try:
            prompt = self._LLM_PROMPT.format(**kwargs)
            response = self._llm.invoke(prompt)

            # Extract text from response
            text = response if isinstance(response, str) else str(response)
            if hasattr(response, "content"):
                text = response.content

            # Parse JSON from response
            return self._parse_llm_response(text)
        except Exception:
            return None

    @staticmethod
    def _parse_llm_response(text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON object from LLM response text."""
        import json as _json

        # Try direct parse
        text = text.strip()
        if text.startswith("```"):
            # Strip markdown code fences
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return _json.loads(text)
        except _json.JSONDecodeError:
            pass

        # Try to find JSON object in text
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return _json.loads(text[start:end + 1])
            except _json.JSONDecodeError:
                pass

        return None


# ── Vulnerability report creation ────────────────────────────────

class CreateVulnerabilityReportTool(BaseTool):
    """Record a confirmed or likely vulnerability finding."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="create_vulnerability_report",
                description="Record a vulnerability finding in the audit report. "
                "Use this for confirmed or likely findings after validation. "
                "Each finding must include title, file, vulnerability type, severity, and evidence.",
                parameters={
                    "title": {
                        "type": "string",
                        "description": "Short descriptive title for the vulnerability",
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "File where the vulnerability exists",
                    },
                    "line_start": {
                        "type": "integer",
                        "description": "Start line number",
                    },
                    "line_end": {
                        "type": "integer",
                        "description": "End line number",
                    },
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Category: sql_injection, xss, command_injection, path_traversal, ssrf, deserialization, auth_bypass, hardcoded_secret, weak_crypto, idor, xxe, ssti, csrf, race_condition",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity: critical, high, medium, low, info",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence 0.0-1.0",
                    },
                    "code_snippet": {
                        "type": "string",
                        "description": "Exact code snippet from read_file output (no paraphrasing)",
                    },
                    "source": {
                        "type": "string",
                        "description": "Source of user input (entry point)",
                    },
                    "sink": {
                        "type": "string",
                        "description": "Dangerous function where input is used",
                    },
                    "suggestion": {
                        "type": "string",
                        "description": "Recommended fix",
                    },
                    "cwe_id": {
                        "type": "string",
                        "description": "CWE identifier (e.g., CWE-89)",
                    },
                    "needs_verification": {
                        "type": "boolean",
                        "description": "Whether this finding needs verification (default: true for high/critical)",
                    },
                    "poc": {
                        "type": "string",
                        "description": "Proof-of-concept code or steps to reproduce the vulnerability",
                    },
                    "impact": {
                        "type": "string",
                        "description": "Description of what an attacker could achieve by exploiting this",
                    },
                    "cvss_score": {
                        "type": "number",
                        "description": "CVSS v3.1 base score (0.0-10.0) if known",
                    },
                },
                required=["title", "file_path", "vulnerability_type", "severity", "code_snippet"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        import os

        project_root = (runtime_context or {}).get("project_root", ".")
        file_path = args.get("file_path", "")
        severity = args.get("severity", "medium").lower()
        confidence = float(args.get("confidence", 0.5))

        # Validate file existence
        full_path = os.path.join(project_root, file_path)
        file_exists = os.path.exists(full_path)

        if not file_exists:
            return {
                "error": f"File does not exist: {file_path}. Cannot create finding for nonexistent file.",
                "status": "rejected",
            }

        if severity not in SEVERITY_LEVELS:
            severity = "medium"

        confidence = max(0.0, min(1.0, confidence))

        # Auto-set needs_verification for high/critical
        needs_verification = args.get("needs_verification", severity in ("critical", "high"))

        # Auto-generate suggestion if missing
        suggestion = args.get("suggestion", "")
        if not suggestion:
            suggestion = _get_recommendation(args.get("vulnerability_type", ""))

        # Validate cvss_score
        cvss_score = args.get("cvss_score")
        if cvss_score is not None:
            cvss_score = max(0.0, min(10.0, float(cvss_score)))

        finding_id = f" finding-{str(uuid.uuid4())[:8]}"

        return {
            "id": finding_id,
            "title": args.get("title", ""),
            "description": args.get("description", ""),
            "file_path": file_path,
            "line_start": int(args.get("line_start", 0)),
            "line_end": int(args.get("line_end", 0)),
            "vulnerability_type": args.get("vulnerability_type", ""),
            "severity": severity,
            "confidence": confidence,
            "code_snippet": args.get("code_snippet", ""),
            "source": args.get("source", ""),
            "sink": args.get("sink", ""),
            "suggestion": suggestion,
            "cwe_id": args.get("cwe_id", ""),
            "needs_verification": needs_verification,
            "poc": args.get("poc", ""),
            "impact": args.get("impact", ""),
            "cvss_score": cvss_score,
            "file_exists": file_exists,
            "status": "recorded",
        }
