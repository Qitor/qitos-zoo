"""Dataflow analysis tool — trace user input from source to sink."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


# ── Source and sink patterns ─────────────────────────────────────

SOURCE_PATTERNS = {
    "python": [
        r"request\.(args|form|data|json|values|files|cookies|headers)",
        r"flask\.request\.",
        r"req\.(query|body|params|headers|cookies)",
        r"input\(",
        r"sys\.argv",
        r"os\.environ",
        r"os\.getenv",
    ],
    "javascript": [
        r"req\.(query|body|params|headers|cookies)",
        r"request\.(query|body|params)",
        r"process\.argv",
        r"window\.location",
        r"document\.URL",
        r"location\.search",
        r"location\.hash",
    ],
    "php": [
        r"\$_GET",
        r"\$_POST",
        r"\$_REQUEST",
        r"\$_COOKIE",
        r"\$_SERVER",
        r"\$_FILES",
    ],
    "java": [
        r"request\.getParameter",
        r"request\.getHeader",
        r"request\.getInputStream",
        r"request\.getReader",
    ],
}

SINK_PATTERNS = {
    "python": [
        (r"os\.system\s*\(", "command_injection"),
        (r"os\.popen\s*\(", "command_injection"),
        (r"subprocess\.(call|run|Popen|check_output)\s*\(.*shell\s*=\s*True", "command_injection"),
        (r"eval\s*\(", "code_injection"),
        (r"exec\s*\(", "code_injection"),
        (r"cursor\.execute\s*\(", "sql_injection"),
        (r"\.raw\s*\(", "sql_injection"),
        (r"open\s*\(", "path_traversal"),
        (r"send_file\s*\(", "path_traversal"),
        (r"requests\.get\s*\(", "ssrf"),
        (r"requests\.post\s*\(", "ssrf"),
        (r"pickle\.loads\s*\(", "deserialization"),
        (r"yaml\.load\s*\(", "deserialization"),
        (r"render_template_string\s*\(", "ssti"),
    ],
    "javascript": [
        (r"eval\s*\(", "code_injection"),
        (r"exec\s*\(", "command_injection"),
        (r"execSync\s*\(", "command_injection"),
        (r"spawn\s*\(", "command_injection"),
        (r"\.query\s*\(", "sql_injection"),
        (r"innerHTML\s*=", "xss"),
        (r"document\.write\s*\(", "xss"),
        (r"fs\.readFile\s*\(", "path_traversal"),
        (r"fetch\s*\(", "ssrf"),
    ],
    "php": [
        (r"system\s*\(", "command_injection"),
        (r"exec\s*\(", "command_injection"),
        (r"shell_exec\s*\(", "command_injection"),
        (r"passthru\s*\(", "command_injection"),
        (r"eval\s*\(", "code_injection"),
        (r"mysql_query\s*\(", "sql_injection"),
        (r"include\s*\(", "path_traversal"),
        (r"require\s*\(", "path_traversal"),
        (r"file_get_contents\s*\(", "path_traversal"),
        (r"unserialize\s*\(", "deserialization"),
        (r"echo\s+.*\$_", "xss"),
    ],
    "java": [
        (r"Runtime\.exec\s*\(", "command_injection"),
        (r"Statement\.execute\s*\(", "sql_injection"),
        (r"ObjectInputStream\s*\(", "deserialization"),
        (r"XMLDecoder\s*\(", "deserialization"),
        (r"FileInputStream\s*\(", "path_traversal"),
    ],
}


def _detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".php": "php",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".sh": "shell",
    }
    _, ext = os.path.splitext(file_path)
    return ext_map.get(ext, "")


class DataflowAnalysisTool(BaseTool):
    """Trace data flow from user input sources to dangerous sinks.

    Uses rule-based pattern matching by default. When an LLM is provided,
    falls back to LLM-based analysis for ambiguous or complex flows.
    """

    _LLM_PROMPT = """\
Analyze the following code for data flow vulnerabilities. Determine if user input
can reach a dangerous sink without proper sanitization.

## Code
File: {file_path}
```
{code}
```

## Source
Line {source_line}: {source_match}

## Sink
Line {sink_line}: {sink_match} (type: {vuln_type})

Respond in this EXACT JSON format:
{{
  "is_reachable": true/false,
  "confidence": 0.0-1.0,
  "sanitizers_found": ["list of sanitizers or validators in the path"],
  "data_flow_description": "step-by-step description of how data flows from source to sink",
  "verdict": "confirmed|likely|uncertain|false_positive"
}}"""

    def __init__(self, llm=None):
        self._llm = llm
        super().__init__(
            ToolSpec(
                name="dataflow_analysis",
                description="Analyze data flow to trace user input from source (entry point) "
                "to sink (dangerous function). Helps confirm if a vulnerability is "
                "reachable. Provide a file path and optionally a function name to analyze.",
                parameters={
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze",
                    },
                    "function_name": {
                        "type": "string",
                        "description": "Specific function to analyze (optional)",
                    },
                    "source_var": {
                        "type": "string",
                        "description": "Variable name to trace from source (optional)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        file_path = args.get("file_path", "")
        function_name = args.get("function_name", "")
        source_var = args.get("source_var", "")

        full_path = os.path.join(project_root, file_path)
        if not os.path.exists(full_path):
            return {"error": f"File not found: {file_path}", "flows": []}

        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        language = _detect_language(file_path)
        if not language:
            language = self._detect_language_from_content(content)

        lines = content.split("\n")
        flows = []

        # Find sources
        source_matches = self._find_sources(lines, language)
        sink_matches = self._find_sinks(lines, language)

        # If function_name specified, filter to that function's scope
        if function_name:
            func_start, func_end = self._find_function_scope(lines, function_name, language)
            if func_start is not None:
                source_matches = [(l, m) for l, m in source_matches if func_start <= l <= func_end]
                sink_matches = [(l, m, t) for l, m, t in sink_matches if func_start <= l <= func_end]

        # If source_var specified, filter sources to those involving that variable
        if source_var:
            source_matches = [(l, m) for l, m in source_matches if source_var in m]

        # Build flow traces: for each source-sink pair, check if there's a plausible path
        for src_line, src_match in source_matches:
            for sink_line, sink_match, vuln_type in sink_matches:
                if sink_line > src_line:
                    # Extract variable assignments between source and sink
                    vars_assigned = self._trace_vars(lines, src_line, sink_line, language)
                    flows.append({
                        "source_line": src_line + 1,
                        "source_match": src_match.strip(),
                        "sink_line": sink_line + 1,
                        "sink_match": sink_match.strip(),
                        "vulnerability_type": vuln_type,
                        "intermediate_vars": vars_assigned,
                        "reachability": "likely" if vars_assigned else "possible",
                    })

        return {
            "file": file_path,
            "language": language,
            "sources_found": len(source_matches),
            "sinks_found": len(sink_matches),
            "flows": flows[:20],
        }

    def _llm_analyze_flow(
        self, content: str, file_path: str, src_line: int, src_match: str,
        sink_line: int, sink_match: str, vuln_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Use LLM to analyze whether a source-to-sink flow is reachable."""
        if not self._llm:
            return None
        try:
            prompt = self._LLM_PROMPT.format(
                file_path=file_path,
                code=content[:4000],
                source_line=src_line,
                source_match=src_match.strip(),
                sink_line=sink_line,
                sink_match=sink_match.strip(),
                vuln_type=vuln_type,
            )
            response = self._llm.invoke(prompt)
            text = response if isinstance(response, str) else str(response)
            if hasattr(response, "content"):
                text = response.content
            return self._parse_llm_response(text)
        except Exception:
            return None

    @staticmethod
    def _parse_llm_response(text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response."""
        import json as _json
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)
        try:
            return _json.loads(text)
        except _json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return _json.loads(text[start:end + 1])
            except _json.JSONDecodeError:
                pass
        return None

    def _find_sources(self, lines: List[str], language: str) -> List[tuple]:
        """Find user input sources in code."""
        matches = []
        patterns = SOURCE_PATTERNS.get(language, [])
        for i, line in enumerate(lines):
            for pat in patterns:
                if re.search(pat, line):
                    matches.append((i, line))
                    break
        return matches

    def _find_sinks(self, lines: List[str], language: str) -> List[tuple]:
        """Find dangerous sinks in code."""
        matches = []
        patterns = SINK_PATTERNS.get(language, [])
        for i, line in enumerate(lines):
            for pat, vuln_type in patterns:
                if re.search(pat, line):
                    matches.append((i, line, vuln_type))
                    break
        return matches

    def _find_function_scope(self, lines: List[str], name: str, language: str):
        """Find start/end line of a function definition."""
        if language == "python":
            pat = re.compile(r"^\s*def\s+" + re.escape(name) + r"\s*\(")
        elif language == "javascript":
            pat = re.compile(r"(function\s+" + re.escape(name) + r"|const\s+" + re.escape(name) + r"\s*=\s*(async\s+)?function|(async\s+)?function\s+" + re.escape(name) + r")")
        elif language == "java":
            pat = re.compile(r"(public|private|protected)?\s*(static\s+)?\w+\s+" + re.escape(name) + r"\s*\(")
        else:
            pat = re.compile(re.escape(name))

        start = None
        base_indent = 0
        for i, line in enumerate(lines):
            if pat.search(line):
                start = i
                if language == "python":
                    base_indent = len(line) - len(line.lstrip())
                break

        if start is None:
            return None, None

        # Find end
        end = start
        if language == "python":
            for i in range(start + 1, len(lines)):
                stripped = lines[i].strip()
                if not stripped:
                    end = i
                    continue
                indent = len(lines[i]) - len(lines[i].lstrip())
                if indent <= base_indent and stripped:
                    break
                end = i
        else:
            # Simple heuristic: look for closing brace
            depth = 0
            found_open = False
            for i in range(start, min(start + 200, len(lines))):
                depth += lines[i].count("{") - lines[i].count("}")
                if "{" in lines[i]:
                    found_open = True
                if found_open and depth <= 0:
                    end = i
                    break
                end = i

        return start, end

    def _trace_vars(self, lines: List[str], src_line: int, sink_line: int, language: str) -> List[str]:
        """Extract variable assignments between source and sink."""
        vars_found = []
        assign_pat = re.compile(r"(\w+)\s*=\s*")
        for i in range(src_line, sink_line + 1):
            if i < len(lines):
                for m in assign_pat.finditer(lines[i]):
                    var = m.group(1)
                    if var not in ("if", "for", "while", "with", "try", "elif", "else", "return", "import", "from", "class", "def"):
                        vars_found.append(var)
        return list(dict.fromkeys(vars_found))[:10]

    def _detect_language_from_content(self, content: str) -> str:
        """Fallback language detection from content."""
        if "def " in content and "import " in content:
            return "python"
        if "function " in content and ("const " in content or "var " in content):
            return "javascript"
        if "<?php" in content or "$_GET" in content:
            return "php"
        if "public class" in content or "import java." in content:
            return "java"
        return "unknown"
