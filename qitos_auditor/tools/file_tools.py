"""File reading, scanning, and pattern matching tools for DeepAudit.

Tools:
- read_file: Read file content with line range and path validation
- smart_scan: Semantic code search combining grep with file type awareness
- pattern_match: Regex-based vulnerability pattern scanning
- code_analysis: LLM-powered deep code analysis
- extract_function: Extract a specific function's source code
- quick_audit: Rapid scan of a single file for obvious issues
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec

# ── Shared constants ───────────────────────────────────────────────────

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules",
    ".venv", "venv", "dist", "build", ".next", ".turbo",
    "coverage", ".pytest_cache", ".mypy_cache", ".cache",
}

CODE_FILE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
    ".rb", ".php", ".rs", ".kt", ".sh", ".bash", ".zsh",
}

MANIFEST_FILES = {
    "requirements.txt", "pyproject.toml", "package.json",
    "Cargo.toml", "go.mod", "Gemfile", "pom.xml",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
}

# Vulnerability pattern categories (from DeepAudit's PatternMatchTool)
VULN_PATTERNS = {
    "sql_injection": [
        (r'execute\s*\(\s*["\'].*%s', "Python SQL string formatting"),
        (r'\.raw\s*\(\s*["\'].*\+', "Django raw SQL concatenation"),
        (r'\.query\s*\(\s*["\'].*\+', "SQL query concatenation"),
        (r'cursor\.execute\s*\(.*format', "Cursor execute with format"),
        (r'\$\{.*\}.*SELECT|INSERT|UPDATE|DELETE', "Template literal SQL injection"),
        (r'mysql_query\s*\(\s*["\'].*\$|mysqli_query\s*\(\s*["\'].*\$', "PHP SQL injection"),
    ],
    "xss": [
        (r'\.innerHTML\s*=', "Direct innerHTML assignment"),
        (r'document\.write\s*\(', "document.write usage"),
        (r'v-html\s*=', "Vue.js v-html directive"),
        (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        (r'\|\s*safe\b', "Django template |safe filter"),
        (r'echo\s+.*\$_GET|echo\s+.*\$_POST|echo\s+.*\$_REQUEST', "PHP unescaped output"),
    ],
    "command_injection": [
        (r'os\.system\s*\(', "os.system call"),
        (r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', "subprocess with shell=True"),
        (r'exec\s*\(', "exec() call"),
        (r'eval\s*\(', "eval() call"),
        (r'child_process\.exec\s*\(', "Node.js child_process.exec"),
        (r'shell_exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\(', "PHP command execution"),
    ],
    "path_traversal": [
        (r'open\s*\(\s*.*\+|open\s*\(\s*.*format|open\s*\(\s*.*%', "Python open with user input"),
        (r'os\.path\.join\s*\(.*request|os\.path\.join\s*.*input', "Path join with user input"),
        (r'file_get_contents\s*\(\s*.*\$_GET|file_get_contents\s*\(\s*.*\$_POST', "PHP file_get_contents with user input"),
        (r'include\s*\(\s*.*\$_GET|require\s*\(\s*.*\$_GET', "PHP include with user input"),
        (r'readfile\s*\(\s*.*\$|fopen\s*\(\s*.*\$', "PHP file read with user variable"),
    ],
    "ssrf": [
        (r'requests\.(get|post|put|delete)\s*\(.*url.*request|requests\.(get|post).*input', "Python requests with user URL"),
        (r'urllib\.request\.urlopen\s*\(.*request|urllib\.request\.urlopen.*input', "urllib with user URL"),
        (r'file_get_contents\s*\(\s*.*\$.*url|curl_exec\s*\(', "PHP SSRF via curl/file_get_contents"),
        (r'fetch\s*\(.*req\.|axios\.(get|post)\s*\(.*req\.', "Node.js fetch/axios with user URL"),
    ],
    "deserialization": [
        (r'pickle\.loads?\s*\(', "Python pickle deserialization"),
        (r'yaml\.load\s*\([^)]*\)(?!.*Loader)', "yaml.load without safe Loader"),
        (r'unserialize\s*\(', "PHP unserialize"),
        (r'ObjectInputStream', "Java ObjectInputStream deserialization"),
        (r'Marshal\.load|Marshal\.restore', "Ruby Marshal deserialization"),
    ],
    "hardcoded_secret": [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
        (r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded API key"),
        (r'(?i)(secret|token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret/token"),
        (r'(?i)(database_url|db_password)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded database URL"),
        (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Hardcoded private key"),
    ],
    "weak_crypto": [
        (r'hashlib\.(md5|sha1)\s*\(', "Weak hash algorithm (MD5/SHA1)"),
        (r'Crypto\.Cipher\.(DES|RC4|Blowfish)', "Weak encryption algorithm"),
        (r'cipher\s*=\s*["\'](AES|DES).*/(ECB|CBC)', "Cipher with potential weak mode"),
        (r'mcrypt\(|openssl_encrypt\s*\(.*DES|openssl_encrypt\s*\(.*RC4', "PHP weak crypto"),
    ],
}


# ── Helper ─────────────────────────────────────────────────────────────

def _resolve_path(workspace_root: str, path: str) -> Path:
    """Resolve and validate a file path within the workspace."""
    workspace = Path(workspace_root).resolve()
    target = (workspace / path).resolve() if not os.path.isabs(path) else Path(path).resolve()
    # Security: prevent path traversal outside workspace
    try:
        target.relative_to(workspace)
    except ValueError:
        raise ValueError(f"Path traversal blocked: {path} is outside workspace")
    return target


def _iter_files(workspace_root: str, file_pattern: str = "") -> List[Path]:
    """Iterate code files in workspace, optionally filtered by glob pattern."""
    root = Path(workspace_root).resolve()
    files = []
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for name in names:
            fpath = Path(dirpath) / name
            if file_pattern:
                import fnmatch
                if not fnmatch.fnmatch(str(fpath.relative_to(root)), file_pattern):
                    continue
            if fpath.suffix.lower() in CODE_FILE_EXTENSIONS or fpath.name in MANIFEST_FILES:
                files.append(fpath)
    return files


def _read_file_content(path: Path, start_line: int = 0, end_line: int = 0, max_bytes: int = 400_000) -> Optional[str]:
    """Read file content with optional line range."""
    try:
        raw = path.read_bytes()
    except Exception:
        return None
    if b"\x00" in raw:
        return None
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="ignore")
    if start_line > 0 or end_line > 0:
        lines = text.splitlines()
        s = max(0, start_line - 1) if start_line > 0 else 0
        e = end_line if end_line > 0 else len(lines)
        text = "\n".join(lines[s:e])
    return text


# ── Tool implementations ───────────────────────────────────────────────

class ReadFileTool(BaseTool):
    """Read file content with line range support and path validation."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="read_file",
                description="Read the content of a file in the target codebase. "
                "Use this to examine source code before reporting findings. "
                "You MUST read a file before claiming a vulnerability exists in it.",
                parameters={
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file from the project root",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Start line number (1-based, optional)",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "End line number (inclusive, optional)",
                    },
                },
                required=["path"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        path_str = str(args.get("path", ""))
        start_line = int(args.get("start_line", 0))
        end_line = int(args.get("end_line", 0))
        try:
            target = _resolve_path(self.workspace_root, path_str)
        except ValueError as e:
            return {"error": str(e), "path": path_str, "content": None}

        if not target.exists():
            return {"error": "File not found", "path": path_str, "content": None}
        if not target.is_file():
            return {"error": "Path is not a file", "path": path_str, "content": None}

        content = _read_file_content(target, start_line, end_line)
        if content is None:
            return {"error": "Could not read file (binary or encoding issue)", "path": path_str, "content": None}

        # Add line numbers
        lines = content.splitlines()
        total_lines = _read_file_content(target)
        total_count = len(total_lines.splitlines()) if total_lines else 0

        return {
            "path": path_str,
            "content": content,
            "total_lines": total_count,
            "showing_lines": f"{start_line or 1}-{end_line or total_count}",
        }


class SmartScanTool(BaseTool):
    """Semantic code search combining grep with file type awareness."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="smart_scan",
                description="Scan the codebase for high-risk patterns and file types. "
                "Returns a summary of potentially risky files organized by category. "
                "Use during recon to identify areas that need deeper analysis.",
                parameters={
                    "query": {
                        "type": "string",
                        "description": "Search query or category: 'sql', 'xss', 'command', 'secrets', 'config', 'deps', 'all'",
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "Optional glob pattern to filter files (e.g. '*.py', 'src/**/*.js')",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 50)",
                    },
                },
                required=["query"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = str(args.get("query", "all")).lower()
        file_pattern = str(args.get("file_pattern", ""))
        max_results = int(args.get("max_results", 50))

        files = _iter_files(self.workspace_root, file_pattern)
        results = []

        # Category-based scanning
        categories_to_scan = []
        if query == "all":
            categories_to_scan = list(VULN_PATTERNS.keys())
        else:
            # Map query aliases
            query_map = {
                "sql": "sql_injection", "sqli": "sql_injection",
                "xss": "xss", "cmd": "command_injection", "command": "command_injection", "rce": "command_injection",
                "path": "path_traversal", "traversal": "path_traversal", "lfi": "path_traversal",
                "ssrf": "ssrf",
                "deser": "deserialization", "deserialization": "deserialization",
                "secret": "hardcoded_secret", "secrets": "hardcoded_secret", "creds": "hardcoded_secret",
                "crypto": "weak_crypto", "weak": "weak_crypto",
            }
            category = query_map.get(query, query)
            if category in VULN_PATTERNS:
                categories_to_scan = [category]

        for fpath in files:
            if len(results) >= max_results:
                break
            content = _read_file_content(fpath, max_bytes=200_000)
            if not content:
                continue
            rel = os.path.relpath(fpath, self.workspace_root)
            for category in categories_to_scan:
                patterns = VULN_PATTERNS.get(category, [])
                for pattern, desc in patterns:
                    try:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                    except re.error:
                        continue
                    for m in matches[:3]:  # Max 3 matches per pattern per file
                        line_num = content[:m.start()].count("\n") + 1
                        line_text = content.splitlines()[line_num - 1].strip() if line_num <= len(content.splitlines()) else ""
                        results.append({
                            "file": rel,
                            "line": line_num,
                            "category": category,
                            "pattern_description": desc,
                            "code": line_text[:200],
                        })
                        if len(results) >= max_results:
                            break

        return {
            "query": query,
            "total_matches": len(results),
            "results": results,
            "files_scanned": len(files),
        }


class PatternMatchTool(BaseTool):
    """Regex-based vulnerability pattern scanning across the codebase."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="pattern_match",
                description="Scan for specific vulnerability patterns using regex. "
                "Use this after external scanners to find patterns they may miss. "
                "Categories: sql_injection, xss, command_injection, path_traversal, "
                "ssrf, deserialization, hardcoded_secret, weak_crypto",
                parameters={
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for",
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "Optional glob pattern to filter files",
                    },
                    "category": {
                        "type": "string",
                        "description": "Vulnerability category to use predefined patterns",
                    },
                },
                required=[],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        custom_pattern = str(args.get("pattern", ""))
        file_pattern = str(args.get("file_pattern", ""))
        category = str(args.get("category", ""))

        patterns_to_run = []
        if category and category in VULN_PATTERNS:
            for pat, desc in VULN_PATTERNS[category]:
                patterns_to_run.append((pat, desc, category))
        elif custom_pattern:
            patterns_to_run.append((custom_pattern, "Custom pattern", "custom"))

        if not patterns_to_run:
            return {"error": "No pattern or category specified", "results": []}

        files = _iter_files(self.workspace_root, file_pattern)
        results = []

        for fpath in files:
            content = _read_file_content(fpath, max_bytes=200_000)
            if not content:
                continue
            rel = os.path.relpath(fpath, self.workspace_root)
            for pattern, desc, cat in patterns_to_run:
                try:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                except re.error as e:
                    results.append({"error": f"Invalid regex: {e}", "pattern": pattern})
                    continue
                for m in matches[:5]:
                    line_num = content[:m.start()].count("\n") + 1
                    line_text = content.splitlines()[line_num - 1].strip() if line_num <= len(content.splitlines()) else ""
                    results.append({
                        "file": rel,
                        "line": line_num,
                        "category": cat,
                        "description": desc,
                        "match": m.group()[:100],
                        "context": line_text[:200],
                    })

        return {"total_matches": len(results), "results": results, "files_scanned": len(files)}


class CodeAnalysisTool(BaseTool):
    """LLM-powered deep code analysis of a single file."""

    def __init__(self, workspace_root: str = ".", llm=None):
        self.workspace_root = os.path.abspath(workspace_root)
        self._llm = llm
        super().__init__(
            ToolSpec(
                name="code_analysis",
                description="Perform deep security analysis of a specific file. "
                "Use this for files that smart_scan or pattern_match flagged as suspicious. "
                "Returns detailed vulnerability assessment with source/sink tracking.",
                parameters={
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze",
                    },
                    "analysis_type": {
                        "type": "string",
                        "description": "Type of analysis: 'security' (default), 'dataflow', 'full'",
                    },
                },
                required=["file_path"],
                timeout_s=300.0,
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        path_str = str(args.get("file_path", ""))
        analysis_type = str(args.get("analysis_type", "security"))

        try:
            target = _resolve_path(self.workspace_root, path_str)
        except ValueError as e:
            return {"error": str(e)}

        if not target.exists():
            return {"error": f"File not found: {path_str}"}

        content = _read_file_content(target)
        if not content:
            return {"error": f"Could not read file: {path_str}"}

        # If no LLM, do rule-based analysis
        if self._llm is None:
            return self._rule_based_analysis(path_str, content, analysis_type)

        # LLM-based analysis
        return self._llm_analysis(path_str, content, analysis_type)

    def _rule_based_analysis(self, path_str: str, content: str, analysis_type: str) -> Dict[str, Any]:
        """Fallback rule-based analysis when no LLM is available."""
        findings = []
        for category, patterns in VULN_PATTERNS.items():
            for pattern, desc in patterns:
                try:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    continue
                for m in matches[:3]:
                    line_num = content[:m.start()].count("\n") + 1
                    line_text = content.splitlines()[line_num - 1].strip() if line_num <= len(content.splitlines()) else ""
                    findings.append({
                        "category": category,
                        "line": line_num,
                        "description": desc,
                        "code": line_text[:200],
                        "confidence": 0.4,  # Low confidence for rule-based
                    })

        # Extract functions (Python)
        functions = []
        if path_str.endswith(".py"):
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions.append({
                            "name": node.name,
                            "line": node.lineno,
                            "args": [a.arg for a in node.args.args],
                        })
            except SyntaxError:
                pass

        return {
            "file": path_str,
            "analysis_type": analysis_type,
            "method": "rule_based",
            "total_lines": len(content.splitlines()),
            "findings": findings,
            "functions": functions,
        }

    def _llm_analysis(self, path_str: str, content: str, analysis_type: str) -> Dict[str, Any]:
        """LLM-powered deep analysis."""
        import json as json_mod
        prompt = f"""Analyze this source file for security vulnerabilities.

File: {path_str}
Analysis type: {analysis_type}

```{content[:50000]}
```

Return a JSON object with:
- "findings": list of {{"category": str, "severity": str, "line": int, "description": str, "evidence": str, "confidence": float, "recommendation": str}}
- "functions": list of function/method names found
- "summary": brief security assessment
"""
        try:
            response = self._llm(prompt) if callable(self._llm) else str(self._llm)
            # Try to parse JSON from response
            text = str(response)
            # Extract JSON from response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                data = json_mod.loads(text[start:end])
                data["method"] = "llm"
                data["file"] = path_str
                return data
        except Exception:
            pass

        # Fallback to rule-based
        return self._rule_based_analysis(path_str, content, analysis_type)


class ExtractFunctionTool(BaseTool):
    """Extract a specific function's source code from a file."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="extract_function",
                description="Extract the source code of a specific function from a file. "
                "Use this to examine individual functions during verification.",
                parameters={
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file",
                    },
                    "function_name": {
                        "type": "string",
                        "description": "Name of the function to extract",
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "Approximate line number of the function (optional hint)",
                    },
                    "include_imports": {
                        "type": "boolean",
                        "description": "If true, include import statements from the top of the file (Python only)",
                    },
                },
                required=["file_path", "function_name"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        path_str = str(args.get("file_path", ""))
        func_name = str(args.get("function_name", ""))
        include_imports = bool(args.get("include_imports", False))

        try:
            target = _resolve_path(self.workspace_root, path_str)
        except ValueError as e:
            return {"error": str(e)}

        if not target.exists():
            return {"error": f"File not found: {path_str}"}

        content = _read_file_content(target)
        if not content:
            return {"error": f"Could not read file: {path_str}"}

        # Python: use AST for precise extraction
        if path_str.endswith(".py"):
            return self._extract_python(content, func_name, path_str, include_imports)

        # Other languages: regex-based
        return self._extract_regex(content, func_name, path_str)

    def _extract_python(self, content: str, func_name: str, path_str: str, include_imports: bool = False) -> Dict[str, Any]:
        """Extract Python function using AST."""
        try:
            tree = ast.parse(content)
            lines = content.splitlines()
        except SyntaxError:
            return self._extract_regex(content, func_name, path_str)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                start = node.lineno
                end = node.end_lineno or start
                func_source = "\n".join(lines[start - 1 : end])

                imports_section = ""
                if include_imports:
                    import_lines = []
                    for n in ast.iter_child_nodes(tree):
                        if isinstance(n, (ast.Import, ast.ImportFrom)):
                            import_lines.append(lines[n.lineno - 1])
                    if import_lines:
                        imports_section = "\n".join(import_lines) + "\n\n"

                return {
                    "file": path_str,
                    "function_name": func_name,
                    "start_line": start,
                    "end_line": end,
                    "source": imports_section + func_source if include_imports else func_source,
                    "args": [a.arg for a in node.args.args],
                }

        return {"error": f"Function '{func_name}' not found in {path_str}"}

    def _extract_regex(self, content: str, func_name: str, path_str: str) -> Dict[str, Any]:
        """Extract function using regex (for non-Python files)."""
        # Generic function pattern
        patterns = [
            rf'(?:function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{)',  # JS/PHP
            rf'(?:def\s+{re.escape(func_name)}\s*\()',  # Python fallback
            rf'(?:public|private|protected|static)\s+\w+\s+{re.escape(func_name)}\s*\(',  # Java
            rf'func\s+{re.escape(func_name)}\s*\(',  # Go
            rf'def\s+{re.escape(func_name)}\s*',  # Ruby
        ]
        lines = content.splitlines()
        for pattern in patterns:
            for i, line in enumerate(lines):
                if re.search(pattern, line):
                    # Extract until closing brace (simple heuristic)
                    start = i + 1
                    brace_count = 0
                    end = min(start + 100, len(lines))
                    for j in range(i, min(i + 100, len(lines))):
                        brace_count += lines[j].count("{") - lines[j].count("}")
                        if brace_count <= 0 and j > i and "{" in "".join(lines[i:j+1]):
                            end = j + 1
                            break
                    func_source = "\n".join(lines[i:end])
                    return {
                        "file": path_str,
                        "function_name": func_name,
                        "start_line": start,
                        "end_line": end,
                        "source": func_source,
                    }
        return {"error": f"Function '{func_name}' not found in {path_str}"}


class QuickAuditTool(BaseTool):
    """Rapid scan of a single file for obvious security issues."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="quick_audit",
                description="Rapid security audit of a single file. "
                "Scans for all vulnerability categories at once. "
                "Use for quick triage of suspicious files.",
                parameters={
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to audit",
                    },
                },
                required=["file_path"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        path_str = str(args.get("file_path", ""))
        try:
            target = _resolve_path(self.workspace_root, path_str)
        except ValueError as e:
            return {"error": str(e)}

        if not target.exists():
            return {"error": f"File not found: {path_str}"}

        content = _read_file_content(target)
        if not content:
            return {"error": f"Could not read file: {path_str}"}

        findings = []
        severity_map = {
            "sql_injection": "critical",
            "command_injection": "critical",
            "xss": "medium",
            "path_traversal": "high",
            "ssrf": "high",
            "deserialization": "high",
            "hardcoded_secret": "high",
            "weak_crypto": "low",
        }

        for category, patterns in VULN_PATTERNS.items():
            for pattern, desc in patterns:
                try:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    continue
                for m in matches[:3]:
                    line_num = content[:m.start()].count("\n") + 1
                    line_text = content.splitlines()[line_num - 1].strip() if line_num <= len(content.splitlines()) else ""
                    findings.append({
                        "category": category,
                        "severity": severity_map.get(category, "medium"),
                        "line": line_num,
                        "description": desc,
                        "code": line_text[:200],
                        "confidence": 0.5,
                    })

        return {
            "file": path_str,
            "total_lines": len(content.splitlines()),
            "findings_count": len(findings),
            "findings": findings,
            "risk_level": "critical" if any(f["severity"] == "critical" for f in findings)
                            else "high" if any(f["severity"] == "high" for f in findings)
                            else "medium" if findings else "low",
        }


# ── Code Search Tool ────────────────────────────────────────────────

class SearchCodeTool(BaseTool):
    """Search code for keywords or regex patterns with context."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="search_code",
                description="Search codebase for keywords or regex patterns. "
                "Returns matching lines with context. Use this to find specific "
                "functions, variable names, or vulnerability patterns.",
                parameters={
                    "query": {
                        "type": "string",
                        "description": "Search query — keyword or regex pattern",
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "Optional glob pattern to filter files (e.g. '*.py', 'src/**/*.js')",
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context around each match (default: 2)",
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "Case-sensitive search (default: false)",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results (default: 30)",
                    },
                },
                required=["query"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = str(args.get("query", ""))
        file_pattern = str(args.get("file_pattern", ""))
        context_lines = int(args.get("context_lines", 2))
        case_sensitive = bool(args.get("case_sensitive", False))
        max_results = int(args.get("max_results", 30))

        files = _iter_files(self.workspace_root, file_pattern)
        flags = 0 if case_sensitive else re.IGNORECASE
        results = []

        try:
            pattern = re.compile(query, flags)
        except re.error as e:
            return {"error": f"Invalid regex: {e}", "results": []}

        for fpath in files:
            if len(results) >= max_results:
                break
            content = _read_file_content(fpath, max_bytes=200_000)
            if not content:
                continue
            rel = os.path.relpath(fpath, self.workspace_root)
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if len(results) >= max_results:
                    break
                if pattern.search(line):
                    start = max(0, i - context_lines)
                    end = min(len(lines), i + context_lines + 1)
                    context = "\n".join(
                        f"{j+1}: {lines[j]}" for j in range(start, end)
                    )
                    results.append({
                        "file": rel,
                        "line": i + 1,
                        "match": line.strip()[:200],
                        "context": context[:500],
                    })

        return {"query": query, "total_matches": len(results), "results": results, "files_searched": len(files)}


# ── List Files Tool ─────────────────────────────────────────────────

class ListFilesTool(BaseTool):
    """List files in the project directory."""

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = os.path.abspath(workspace_root)
        super().__init__(
            ToolSpec(
                name="list_files",
                description="List files in the project directory. "
                "Use this to understand the project structure during reconnaissance.",
                parameters={
                    "path": {
                        "type": "string",
                        "description": "Directory path to list (default: project root)",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Optional glob pattern to filter files (e.g. '*.py')",
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "List recursively (default: true)",
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory depth (default: 5)",
                    },
                },
                required=[],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rel_path = str(args.get("path", "."))
        pattern = str(args.get("pattern", ""))
        recursive = bool(args.get("recursive", True))
        max_depth = int(args.get("max_depth", 5))

        target = Path(self.workspace_root) / rel_path
        if not target.exists() or not target.is_dir():
            return {"error": f"Directory not found: {rel_path}", "files": []}

        import fnmatch
        files = []
        dirs = []

        for dirpath, dirnames, names in os.walk(target):
            # Skip excluded dirs
            dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith(".")]

            # Check depth
            depth = len(Path(dirpath).relative_to(target).parts)
            if depth >= max_depth:
                dirnames.clear()
                continue

            if not recursive and depth > 0:
                dirnames.clear()

            for name in sorted(names):
                if pattern and not fnmatch.fnmatch(name, pattern):
                    continue
                fpath = Path(dirpath) / name
                rel = os.path.relpath(fpath, self.workspace_root)
                files.append(rel)

            for d in sorted(dirnames):
                dpath = Path(dirpath) / d
                rel = os.path.relpath(dpath, self.workspace_root)
                dirs.append(rel + "/")

        return {
            "path": rel_path,
            "directories": dirs[:100],
            "files": files[:500],
            "total_files": len(files),
            "total_dirs": len(dirs),
        }
