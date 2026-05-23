"""Injection test tools — command injection, SQL injection, XSS, path traversal, SSTI, deserialization.

Each tool tries sandbox execution first (Docker preferred, subprocess fallback),
then falls back to static pattern analysis when sandbox is unavailable.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


# ── Shared helpers ──────────────────────────────────────────────────

def _read_target_file(file_path: str, project_root: str = ".") -> Optional[str]:
    """Read a target file for testing."""
    full_path = os.path.join(project_root, file_path)
    if not os.path.exists(full_path):
        return None
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _detect_language(file_path: str, code: str = "") -> str:
    """Detect language from file extension or content."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".php": "php", ".java": "java", ".go": "go", ".rb": "ruby", ".sh": "shell",
    }
    _, ext = os.path.splitext(file_path)
    if ext in ext_map:
        return ext_map[ext]
    if "<?php" in code:
        return "php"
    if "def " in code and "import " in code:
        return "python"
    if "function " in code and ("var " in code or "const " in code):
        return "javascript"
    return "python"


def _run_sandbox_exec(command: str, timeout: int = 30, project_root: str = ".") -> Dict[str, Any]:
    """Execute a command in sandbox — delegates to sandbox_tools._run_sandbox."""
    from qitos_zoo.qitos_auditor.tools.sandbox_tools import _run_sandbox
    return _run_sandbox(command, timeout=timeout, project_root=project_root)


def _build_python_mock(param_name: str, value: str, code: str) -> str:
    """Build a Python test harness with mocked request/input."""
    return f"""
import sys, os

class MockArgs:
    def __getattr__(self, name): return '{value}'
    def get(self, key, default=None):
        if key == '{param_name}': return '{value}'
        return default

class MockRequest:
    args = MockArgs(); form = MockArgs(); values = MockArgs()

request = MockRequest()
sys.argv = ['test', '{value}']
os.environ['{param_name.upper()}'] = '{value}'
{code}
"""


def _build_javascript_mock(param_name: str, value: str, code: str) -> str:
    """Build a JavaScript test harness with mocked req."""
    return f"""
const req = {{ query: {{ {param_name}: '{value}' }}, body: {{ {param_name}: '{value}' }}, params: {{ {param_name}: '{value}' }} }};
process.argv = ['node', 'test.js', '{value}'];
process.env['{param_name.upper()}'] = '{value}';
{code}
"""


def _build_php_mock(param_name: str, value: str, code: str) -> str:
    """Build a PHP test harness with mocked superglobals."""
    clean = code.strip()
    if clean.startswith("<?php"):
        clean = clean[5:]
    elif clean.startswith("<?"):
        clean = clean[2:]
    if clean.endswith("?>"):
        clean = clean[:-2]
    return f"""$_GET['{param_name}'] = '{value}';
$_POST['{param_name}'] = '{value}';
$_REQUEST['{param_name}'] = '{value}';
{clean.strip()}
"""


def _try_sandbox_exec(test_code: str, language: str, project_root: str = ".", timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Try to execute test code in sandbox. Returns None if sandbox unavailable."""
    cmd_map = {
        "python": f"python3 -c {repr(test_code)}",
        "javascript": f"node -e {repr(test_code)}",
        "php": f"php -r {repr(test_code)}",
        "ruby": f"ruby -e {repr(test_code)}",
        "shell": f"bash -c {repr(test_code)}",
    }
    command = cmd_map.get(language)
    if not command:
        return None
    try:
        result = _run_sandbox_exec(command, timeout=timeout, project_root=project_root)
        if result.get("sandbox") in ("docker", "local"):
            return result
    except Exception:
        pass
    return None


# ── Command Injection Test ──────────────────────────────────────────

class TestCommandInjectionTool(BaseTool):
    """Test for command injection vulnerabilities via sandbox execution."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="test_command_injection",
                description="Test a target file for command injection vulnerabilities. "
                "Executes code in Docker sandbox with mocked input to verify command execution. "
                "Falls back to static analysis when sandbox is unavailable. "
                "Supports PHP, Python, JavaScript, Java, Go, Ruby, Shell.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "Parameter name to inject (default: cmd)",
                    },
                    "test_command": {
                        "type": "string",
                        "description": "Command to attempt (default: id)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, php, python, javascript, java, go, ruby, shell (default: auto)",
                    },
                },
                required=["target_file"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target_file = args.get("target_file", "")
        param_name = args.get("param_name", "cmd")
        test_command = args.get("test_command", "id")
        language = args.get("language", "auto")

        code = _read_target_file(target_file, project_root)
        if code is None:
            return {"error": f"File not found: {target_file}", "vulnerable": False}

        if language == "auto":
            language = _detect_language(target_file, code)

        # Try sandbox execution first
        sandbox_result = self._try_sandbox(code, language, param_name, test_command, project_root)
        if sandbox_result is not None:
            return sandbox_result

        # Fallback: static analysis
        return self._static_analysis(code, language, target_file, param_name, test_command)

    def _try_sandbox(self, code: str, language: str, param: str, cmd: str, project_root: str) -> Optional[Dict[str, Any]]:
        """Try sandbox execution with mocked input."""
        if language == "python":
            test_code = _build_python_mock(param, cmd, code)
        elif language == "javascript":
            test_code = _build_javascript_mock(param, cmd, code)
        elif language == "php":
            test_code = _build_php_mock(param, cmd, code)
        else:
            return None

        result = _try_sandbox_exec(test_code, language, project_root)
        if result is None:
            return None

        output = result.get("stdout", "") + result.get("stderr", "")
        vulnerable = False
        evidence = []

        # Command execution indicators
        cmd_indicators = {
            "uid=": "Command executed (id output)",
            "root:": "Command executed (passwd content)",
            "www-data": "Web user access",
            "nobody": "Low privilege user",
            "daemon:": "Daemon user",
        }
        for pattern, desc in cmd_indicators.items():
            if pattern in output:
                vulnerable = True
                evidence.append(desc)

        if test_command == "id" and "uid=" in output:
            vulnerable = True
            evidence.append("id command executed successfully")
        elif test_command.startswith("echo ") and test_command[5:].strip() in output:
            vulnerable = True
            evidence.append("echo command output detected")

        poc = None
        if vulnerable:
            poc = f"curl 'http://target/?{param}={cmd.replace(' ', '+')}'"

        return {
            "target_file": "",  # filled by caller
            "param_name": param,
            "test_command": cmd,
            "language": language,
            "vulnerable": vulnerable,
            "evidence": evidence,
            "poc": poc,
            "verdict": "confirmed" if vulnerable else "false_positive",
            "output_preview": output[:500],
            "exit_code": result.get("exit_code", -1),
            "method": "sandbox",
        }

    def _static_analysis(self, code: str, language: str, target_file: str, param: str, cmd: str) -> Dict[str, Any]:
        """Static pattern analysis fallback."""
        vulnerable = False
        evidence = []

        patterns = {
            "python": [
                (r"os\.system\s*\(", "os.system call"),
                (r"os\.popen\s*\(", "os.popen call"),
                (r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", "subprocess with shell=True"),
                (r"exec\s*\(", "exec() call"),
                (r"eval\s*\(", "eval() call"),
            ],
            "javascript": [
                (r"child_process\.exec\s*\(", "child_process.exec"),
                (r"child_process\.execSync\s*\(", "child_process.execSync"),
            ],
            "php": [
                (r"system\s*\(", "system() call"),
                (r"exec\s*\(", "exec() call"),
                (r"shell_exec\s*\(", "shell_exec() call"),
                (r"passthru\s*\(", "passthru() call"),
                (r"popen\s*\(", "popen() call"),
            ],
        }
        for pattern, desc in patterns.get(language, []):
            if re.search(pattern, code):
                vulnerable = True
                evidence.append(f"Pattern found: {desc}")

        # Check for user input reachability
        user_input = bool(re.search(r"request\.|req\.|\$_GET|\$_POST|\$_REQUEST", code))
        if vulnerable and not user_input:
            evidence.append("User input reachability unclear")

        return {
            "target_file": target_file,
            "param_name": param,
            "test_command": cmd,
            "language": language,
            "vulnerable": vulnerable and user_input,
            "evidence": evidence,
            "poc": None,
            "verdict": "likely" if (vulnerable and user_input) else "uncertain",
            "method": "static",
        }


# ── SQL Injection Test ──────────────────────────────────────────────

SQL_ERROR_PATTERNS = {
    "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException", r"mysql_fetch"],
    "postgresql": [r"PostgreSQL.*ERROR", r"Warning.*pg_", r"PSQLException"],
    "sqlite": [r"SQLite.*error", r"SQLITE_ERROR", r"sqlite3.OperationalError"],
    "oracle": [r"ORA-\d{5}", r"Oracle.*Driver", r"oracle\.jdbc"],
    "mssql": [r"ODBC SQL Server Driver", r"SqlException", r"Unclosed quotation mark"],
    "generic": [r"SQL syntax", r"sql_error", r"query failed", r"Database error", r"Syntax error.*SQL"],
}


class TestSqlInjectionTool(BaseTool):
    """Test for SQL injection vulnerabilities via sandbox execution."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="test_sql_injection",
                description="Test a target file for SQL injection vulnerabilities. "
                "Executes code in Docker sandbox with mocked database and injected payload. "
                "Falls back to static analysis when sandbox is unavailable.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "Parameter name to inject (default: id)",
                    },
                    "payload": {
                        "type": "string",
                        "description": "SQL injection payload (default: 1' OR '1'='1)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, php, python (default: auto)",
                    },
                    "db_type": {
                        "type": "string",
                        "description": "Database type: mysql, postgresql, sqlite, oracle, mssql (default: sqlite)",
                    },
                },
                required=["target_file"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target_file = args.get("target_file", "")
        param_name = args.get("param_name", "id")
        payload = args.get("payload", "1' OR '1'='1")
        language = args.get("language", "auto")
        db_type = args.get("db_type", "sqlite")

        code = _read_target_file(target_file, project_root)
        if code is None:
            return {"error": f"File not found: {target_file}", "vulnerable": False}

        if language == "auto":
            language = _detect_language(target_file, code)

        # Try sandbox execution with SQLite mock
        sandbox_result = self._try_sandbox(code, language, param_name, payload, project_root)
        if sandbox_result is not None:
            # Also check for SQL error patterns in sandbox output
            output = sandbox_result.get("output_preview", "")
            sql_errors = self._detect_sql_errors(output, db_type)
            if sql_errors:
                sandbox_result["sql_errors_found"] = sql_errors
                sandbox_result["vulnerable"] = True
                sandbox_result["verdict"] = "confirmed"
                sandbox_result["evidence"] = sandbox_result.get("evidence", []) + sql_errors
            return sandbox_result

        # Fallback: static analysis
        sql_errors = self._detect_sql_errors(code, db_type)
        data_leak = self._detect_data_leak(code)
        vulnerable = bool(sql_errors) or data_leak

        return {
            "target_file": target_file,
            "param_name": param_name,
            "payload": payload,
            "language": language,
            "db_type": db_type,
            "vulnerable": vulnerable,
            "sql_errors_found": sql_errors,
            "data_leak_indicators": data_leak,
            "poc": f"curl 'http://target/?{param_name}={payload.replace(chr(39), '%27').replace(' ', '+')}'" if vulnerable else None,
            "verdict": "likely" if vulnerable else "uncertain",
            "method": "static",
        }

    def _try_sandbox(self, code: str, language: str, param: str, payload: str, project_root: str) -> Optional[Dict[str, Any]]:
        """Try sandbox execution with SQLite mock."""
        if language == "python":
            # Build test with SQLite mock
            safe_payload = payload.replace("'", "\\'")
            test_code = f"""
import sqlite3, sys, os

# Create in-memory DB with test data
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute('CREATE TABLE users (id INTEGER, name TEXT, password TEXT)')
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
cursor.execute("INSERT INTO users VALUES (2, 'user', 'pass456')")
conn.commit()

class MockArgs:
    def get(self, key, default=None):
        if key == '{param}': return '''{safe_payload}'''
        return default
class MockRequest:
    args = MockArgs(); form = MockArgs()
request = MockRequest()
sys.argv = ['test']

# Redirect cursor.execute to capture queries
_orig_execute = cursor.execute
_query_log = []
def _logging_execute(query, params=None):
    _query_log.append(query)
    return _orig_execute(query, params) if params else _orig_execute(query)
cursor.execute = _logging_execute

try:
    {code}
except Exception as e:
    print(f"ERROR: {{type(e).__name__}}: {{e}}", file=sys.stderr)

for q in _query_log:
    print(f"QUERY: {{q}}")
"""
            result = _try_sandbox_exec(test_code, "python", project_root, timeout=30)
            if result is None:
                return None

            output = result.get("stdout", "") + result.get("stderr", "")
            vulnerable = False
            evidence = []

            # Check if SQL error appeared
            for dtype in ["sqlite", "generic"]:
                for pattern in SQL_ERROR_PATTERNS.get(dtype, []):
                    if re.search(pattern, output, re.IGNORECASE):
                        vulnerable = True
                        evidence.append(f"SQL error detected: {pattern}")

            # Check if data was leaked
            if "admin" in output and "secret123" in output:
                vulnerable = True
                evidence.append("Database data leaked in output")

            # Check query log for injection patterns
            if "OR '1'='1" in output or "OR 1=1" in output:
                vulnerable = True
                evidence.append("Injection payload reflected in query")

            return {
                "target_file": "",
                "param_name": param,
                "payload": payload,
                "language": language,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "poc": None,
                "verdict": "confirmed" if vulnerable else "false_positive",
                "output_preview": output[:500],
                "exit_code": result.get("exit_code", -1),
                "method": "sandbox",
            }
        return None

    def _detect_sql_errors(self, text: str, db_type: str) -> List[str]:
        found = []
        for dtype in [db_type, "generic"]:
            for pattern in SQL_ERROR_PATTERNS.get(dtype, []):
                if re.search(pattern, text, re.IGNORECASE):
                    found.append(pattern)
        return found

    def _detect_data_leak(self, code: str) -> bool:
        indicators = ["admin", "root", "password", "SELECT.*FROM", "UNION SELECT"]
        return any(re.search(ind, code, re.IGNORECASE) for ind in indicators)


# ── XSS Test ────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
]


class TestXssTool(BaseTool):
    """Test for XSS vulnerabilities via sandbox execution."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="test_xss",
                description="Test a target file for Cross-Site Scripting (XSS) vulnerabilities. "
                "Executes code in sandbox to check if payload is reflected without sanitization. "
                "Falls back to static pattern analysis when sandbox is unavailable.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "Parameter name to inject (default: input)",
                    },
                    "payload": {
                        "type": "string",
                        "description": "XSS payload (default: <script>alert('XSS')</script>)",
                    },
                    "xss_type": {
                        "type": "string",
                        "description": "XSS type: reflected, stored, dom (default: reflected)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, php, python (default: auto)",
                    },
                },
                required=["target_file"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target_file = args.get("target_file", "")
        param_name = args.get("param_name", "input")
        payload = args.get("payload", "<script>alert('XSS')</script>")
        xss_type = args.get("xss_type", "reflected")
        language = args.get("language", "auto")

        code = _read_target_file(target_file, project_root)
        if code is None:
            return {"error": f"File not found: {target_file}", "vulnerable": False}

        if language == "auto":
            language = _detect_language(target_file, code)

        # Try sandbox execution
        sandbox_result = self._try_sandbox(code, language, param_name, payload, project_root)
        if sandbox_result is not None:
            sandbox_result["target_file"] = target_file
            sandbox_result["xss_type"] = xss_type
            return sandbox_result

        # Fallback: static analysis
        return self._static_analysis(code, language, target_file, param_name, payload, xss_type)

    def _try_sandbox(self, code: str, language: str, param: str, payload: str, project_root: str) -> Optional[Dict[str, Any]]:
        """Try sandbox execution to check if XSS payload is reflected."""
        safe_payload = payload.replace("'", "\\'").replace('"', '\\"')

        if language == "python":
            test_code = f"""
import sys

class MockArgs:
    def get(self, key, default=None):
        if key == '{param}': return '''{safe_payload}'''
        return default
class MockRequest:
    args = MockArgs(); form = MockArgs()
request = MockRequest()

# Capture output
_output_buffer = []
import io
sys.stdout = io.StringIO()

try:
    {code}
except Exception as e:
    print(f"ERROR: {{type(e).__name__}}: {{e}}", file=sys.stderr)

captured = sys.stdout.getvalue()
print("OUTPUT_START")
print(captured)
print("OUTPUT_END")
"""
        elif language == "php":
            clean = code.strip()
            if clean.startswith("<?php"): clean = clean[5:]
            elif clean.startswith("<?"): clean = clean[2:]
            if clean.endswith("?>"): clean = clean[:-2]
            test_code = f"""$_GET['{param}'] = '{safe_payload}';
$_POST['{param}'] = '{safe_payload}';
$_REQUEST['{param}'] = '{safe_payload}';
ob_start();
{clean.strip()}
$output = ob_get_clean();
echo "OUTPUT_START\\n" . $output . "\\nOUTPUT_END\\n";
"""
        else:
            return None

        result = _try_sandbox_exec(test_code, language, project_root, timeout=30)
        if result is None:
            return None

        output = result.get("stdout", "")
        vulnerable = False
        evidence = []

        # Check if payload appears unescaped in output
        if payload in output:
            vulnerable = True
            evidence.append("XSS payload reflected unescaped in output")
        elif "&lt;script&gt;" in output:
            evidence.append("Payload was HTML-encoded (partial protection)")
        elif "onerror=" in output or "onload=" in output:
            vulnerable = True
            evidence.append("Event handler payload reflected in output")

        poc = None
        if vulnerable:
            encoded = payload.replace("<", "%3C").replace(">", "%3E").replace("'", "%27")
            poc = f"curl 'http://target/?{param}={encoded}'"

        return {
            "target_file": "",
            "param_name": param,
            "payload": payload,
            "language": language,
            "vulnerable": vulnerable,
            "evidence": evidence,
            "poc": poc,
            "verdict": "confirmed" if vulnerable else "false_positive",
            "output_preview": output[:500],
            "method": "sandbox",
        }

    def _static_analysis(self, code: str, language: str, target_file: str, param: str, payload: str, xss_type: str) -> Dict[str, Any]:
        """Static pattern analysis fallback."""
        vulnerable = False
        evidence = []

        output_patterns = {
            "python": [r"return\s+f?['\"].*\{.*request\.", r"render_template_string\s*\(", r"Markup\s*\(", r"\|safe"],
            "javascript": [r"innerHTML\s*=", r"document\.write\s*\(", r"res\.send\s*\(`[^`]*\$\{"],
            "php": [r"echo\s+.*\$_", r"print\s*\(.*\$_", r"\. *\$_GET", r"\. *\$_POST"],
        }
        for pattern in output_patterns.get(language, []):
            if re.search(pattern, code):
                vulnerable = True
                evidence.append(f"User input directly output: pattern '{pattern}' found")

        encoded = "&lt;script&gt;" in code or "escape(" in code or "htmlspecialchars" in code
        if encoded:
            evidence.append("HTML encoding detected — may mitigate XSS")

        return {
            "target_file": target_file,
            "param_name": param,
            "payload": payload,
            "xss_type": xss_type,
            "language": language,
            "vulnerable": vulnerable and not encoded,
            "evidence": evidence,
            "poc": None,
            "verdict": "likely" if (vulnerable and not encoded) else "uncertain",
            "method": "static",
        }


# ── Path Traversal Test ─────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
]


class TestPathTraversalTool(BaseTool):
    """Test for path traversal vulnerabilities via sandbox execution."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="test_path_traversal",
                description="Test a target file for path traversal / LFI vulnerabilities. "
                "Executes code in sandbox to verify if traversal payload accesses sensitive files. "
                "Falls back to static analysis when sandbox is unavailable.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "Parameter name to inject (default: file)",
                    },
                    "payload": {
                        "type": "string",
                        "description": "Traversal payload (default: ../../../etc/passwd)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, php, python (default: auto)",
                    },
                },
                required=["target_file"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target_file = args.get("target_file", "")
        param_name = args.get("param_name", "file")
        payload = args.get("payload", "../../../etc/passwd")
        language = args.get("language", "auto")

        code = _read_target_file(target_file, project_root)
        if code is None:
            return {"error": f"File not found: {target_file}", "vulnerable": False}

        if language == "auto":
            language = _detect_language(target_file, code)

        # Try sandbox execution
        sandbox_result = self._try_sandbox(code, language, param_name, payload, project_root)
        if sandbox_result is not None:
            sandbox_result["target_file"] = target_file
            return sandbox_result

        # Fallback: static analysis
        return self._static_analysis(code, language, target_file, param_name, payload)

    def _try_sandbox(self, code: str, language: str, param: str, payload: str, project_root: str) -> Optional[Dict[str, Any]]:
        """Try sandbox execution to check if traversal payload reads sensitive files."""
        if language == "python":
            test_code = f"""
import sys, os

class MockArgs:
    def get(self, key, default=None):
        if key == '{param}': return '{payload}'
        return default
class MockRequest:
    args = MockArgs()
request = MockRequest()

try:
    {code}
except Exception as e:
    print(f"ERROR: {{type(e).__name__}}: {{e}}", file=sys.stderr)
"""
            result = _try_sandbox_exec(test_code, "python", project_root, timeout=30)
            if result is None:
                return None

            output = result.get("stdout", "") + result.get("stderr", "")
            vulnerable = False
            evidence = []

            # Check for sensitive file content
            passwd_patterns = [r"root:.*:0:0:", r"daemon:.*:", r"nobody:.*:", r"www-data:"]
            for pattern in passwd_patterns:
                if re.search(pattern, output):
                    vulnerable = True
                    evidence.append("Successfully read /etc/passwd content")
                    break

            # Windows patterns
            if not vulnerable:
                win_patterns = [r"\[fonts\]", r"\[extensions\]", r"for 16-bit app support"]
                for pattern in win_patterns:
                    if re.search(pattern, output, re.IGNORECASE):
                        vulnerable = True
                        evidence.append("Successfully read Windows system file")
                        break

            poc = None
            if vulnerable:
                encoded = payload.replace("../", "..%2f")
                poc = f"curl 'http://target/?{param}={encoded}'"

            return {
                "target_file": "",
                "param_name": param,
                "payload": payload,
                "language": language,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "poc": poc,
                "verdict": "confirmed" if vulnerable else "false_positive",
                "output_preview": output[:500],
                "method": "sandbox",
            }
        return None

    def _static_analysis(self, code: str, language: str, target_file: str, param: str, payload: str) -> Dict[str, Any]:
        """Static pattern analysis fallback."""
        vulnerable = False
        evidence = []

        traversal_patterns = {
            "python": [r"open\s*\([^)]*\+\s*", r"send_file\s*\([^)]*\+\s*", r"os\.path\.join\s*\(.*request\."],
            "javascript": [r"fs\.readFile\s*\([^)]*\+\s*", r"res\.sendFile\s*\([^)]*\+\s*"],
            "php": [r"include\s*\(\s*\$_", r"require\s*\(\s*\$_", r"file_get_contents\s*\(\s*\$_", r"fopen\s*\(\s*\$_"],
        }
        for pattern in traversal_patterns.get(language, []):
            if re.search(pattern, code):
                vulnerable = True
                evidence.append(f"Path concatenation with user input: pattern '{pattern}' found")

        has_validation = bool(re.search(r"abspath|realpath|resolve|secure_filename|basename", code))
        if has_validation:
            evidence.append("Path validation detected — may mitigate traversal")

        return {
            "target_file": target_file,
            "param_name": param,
            "payload": payload,
            "language": language,
            "vulnerable": vulnerable and not has_validation,
            "evidence": evidence,
            "poc": None,
            "verdict": "likely" if (vulnerable and not has_validation) else "uncertain",
            "method": "static",
        }


# ── SSTI Test ───────────────────────────────────────────────────────

SSTI_PAYLOADS = {
    "jinja2": ["{{7*7}}", "{{config}}", "{{''.__class__.__mro__}}"],
    "twig": ["{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}"],
    "freemarker": ["${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\">"],
    "velocity": ["#set($x=7*7)$x", "$class.inspect('java.lang.Runtime')"],
    "smarty": ["{7*7}", "{php}system('id'){/php}"],
}


class TestSstiTool(BaseTool):
    """Test for Server-Side Template Injection (SSTI) via sandbox execution."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="test_ssti",
                description="Test for Server-Side Template Injection (SSTI) vulnerabilities. "
                "Executes code in sandbox to verify if template expressions are evaluated. "
                "Falls back to static pattern analysis when sandbox is unavailable. "
                "Supports Jinja2, Twig, Freemarker, Velocity, Smarty engines.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "Parameter name to inject (default: name)",
                    },
                    "payload": {
                        "type": "string",
                        "description": "SSTI payload (default: {{7*7}})",
                    },
                    "template_engine": {
                        "type": "string",
                        "description": "Engine: auto, jinja2, twig, freemarker, velocity, smarty (default: auto)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, python, php (default: auto)",
                    },
                },
                required=["target_file"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target_file = args.get("target_file", "")
        param_name = args.get("param_name", "name")
        payload = args.get("payload", "{{7*7}}")
        template_engine = args.get("template_engine", "auto")
        language = args.get("language", "auto")

        code = _read_target_file(target_file, project_root)
        if code is None:
            return {"error": f"File not found: {target_file}", "vulnerable": False}

        if language == "auto":
            language = _detect_language(target_file, code)

        if template_engine == "auto":
            if "jinja" in code.lower() or "flask" in code.lower():
                template_engine = "jinja2"
            elif "twig" in code.lower():
                template_engine = "twig"
            elif "freemarker" in code.lower():
                template_engine = "freemarker"
            else:
                template_engine = "jinja2"

        # Try sandbox execution (Python/Jinja2 only for now)
        sandbox_result = self._try_sandbox(code, language, param_name, payload, template_engine, project_root)
        if sandbox_result is not None:
            sandbox_result["target_file"] = target_file
            sandbox_result["template_engine"] = template_engine
            return sandbox_result

        # Fallback: static analysis
        return self._static_analysis(code, language, target_file, param_name, payload, template_engine)

    def _try_sandbox(self, code: str, language: str, param: str, payload: str, engine: str, project_root: str) -> Optional[Dict[str, Any]]:
        """Try sandbox execution for SSTI."""
        if language == "python" and engine == "jinja2":
            safe_payload = payload.replace("'", "\\'")
            test_code = f"""
from jinja2 import Template
import sys

class MockArgs:
    def get(self, key, default=None):
        if key == '{param}': return '''{safe_payload}'''
        return default
class MockRequest:
    args = MockArgs(); form = MockArgs()
request = MockRequest()

try:
    {code}
except Exception as e:
    print(f"ERROR: {{type(e).__name__}}: {{e}}", file=sys.stderr)
"""
            result = _try_sandbox_exec(test_code, "python", project_root, timeout=30)
            if result is None:
                return None

            output = result.get("stdout", "") + result.get("stderr", "")
            vulnerable = False
            evidence = []

            # Check for math expression evaluation
            if "{{7*7}}" in payload and "49" in output:
                vulnerable = True
                evidence.append("Template expression 7*7 evaluated to 49")
            elif "config" in payload.lower() and ("secret" in output.lower() or "debug" in output.lower()):
                vulnerable = True
                evidence.append("Template can access config object")
            elif "id" in payload and ("uid=" in output or "root" in output.lower()):
                vulnerable = True
                evidence.append("SSTI leads to remote code execution")

            poc = None
            if vulnerable:
                encoded = payload.replace("{", "%7B").replace("}", "%7D")
                poc = f"curl 'http://target/?{param}={encoded}'"

            return {
                "target_file": "",
                "param_name": param,
                "payload": payload,
                "language": language,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "poc": poc,
                "verdict": "confirmed" if vulnerable else "false_positive",
                "output_preview": output[:500],
                "method": "sandbox",
            }
        return None

    def _static_analysis(self, code: str, language: str, target_file: str, param: str, payload: str, engine: str) -> Dict[str, Any]:
        """Static pattern analysis fallback."""
        vulnerable = False
        evidence = []

        ssti_patterns = [
            r"render_template_string\s*\(",
            r"Template\s*\(",
            r"\.render\s*\(",
            r"Environment\s*\(",
        ]
        for pattern in ssti_patterns:
            if re.search(pattern, code):
                vulnerable = True
                evidence.append(f"Template rendering with potential user input: pattern '{pattern}' found")

        if "render_template_string" in code and ("f'" in code or 'f"' in code):
            vulnerable = True
            evidence.append("f-string used in render_template_string — direct SSTI risk")

        return {
            "target_file": target_file,
            "param_name": param,
            "payload": payload,
            "template_engine": engine,
            "language": language,
            "vulnerable": vulnerable,
            "evidence": evidence,
            "poc": None,
            "verdict": "likely" if vulnerable else "uncertain",
            "method": "static",
        }


# ── Deserialization Test ────────────────────────────────────────────

class TestDeserializationTool(BaseTool):
    """Test for insecure deserialization vulnerabilities (static analysis only — RCE risk too high for sandbox)."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="test_deserialization",
                description="Test for insecure deserialization vulnerabilities via static analysis. "
                "Checks for pickle.loads, yaml.load, unserialize, ObjectInputStream, etc. "
                "Note: Dynamic testing is intentionally NOT performed due to RCE risk.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, php, python, java, ruby (default: auto)",
                    },
                },
                required=["target_file"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target_file = args.get("target_file", "")
        language = args.get("language", "auto")

        code = _read_target_file(target_file, project_root)
        if code is None:
            return {"error": f"File not found: {target_file}", "vulnerable": False}

        if language == "auto":
            language = _detect_language(target_file, code)

        vulnerable = False
        evidence = []

        dangerous_patterns = {
            "python": [
                (r"pickle\.loads?\s*\(", "pickle.loads/unpickle"),
                (r"yaml\.load\s*\([^)]*\)(?!.*safe_load)", "yaml.load without safe_load"),
                (r"yaml\.load\s*\([^)]*,\s*Loader\s*=\s*yaml\.Loader", "yaml.load with unsafe Loader"),
                (r"marshal\.loads\s*\(", "marshal.loads"),
                (r"shelve\.open\s*\(", "shelve.open"),
            ],
            "php": [
                (r"unserialize\s*\(\s*\$_", "unserialize with user input"),
                (r"unserialize\s*\(", "unserialize call"),
            ],
            "java": [
                (r"ObjectInputStream", "Java ObjectInputStream"),
                (r"readObject\s*\(", "readObject call"),
                (r"XMLDecoder", "XMLDecoder deserialization"),
            ],
            "ruby": [
                (r"Marshal\.load", "Marshal.load"),
                (r"YAML\.load\s*\(", "YAML.load"),
            ],
        }

        for pattern, desc in dangerous_patterns.get(language, []):
            if re.search(pattern, code):
                vulnerable = True
                evidence.append(f"Dangerous deserialization: {desc}")

        user_input_patterns = [r"request\.", r"\$_GET", r"\$_POST", r"req\.", r"input\("]
        has_user_input = any(re.search(p, code) for p in user_input_patterns)

        if vulnerable and has_user_input:
            verdict = "likely"
        elif vulnerable:
            verdict = "uncertain"
        else:
            verdict = "false_positive"

        return {
            "target_file": target_file,
            "language": language,
            "vulnerable": vulnerable,
            "evidence": evidence,
            "user_input_reachable": has_user_input,
            "poc": None,
            "verdict": verdict,
            "method": "static",
        }


# ── Universal Vuln Test ─────────────────────────────────────────────

VULN_TYPE_ALIASES = {
    "cmd": "command_injection",
    "rce": "command_injection",
    "sqli": "sql_injection",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "traversal": "path_traversal",
    "template": "ssti",
    "deser": "deserialization",
}


class VulnTestTool(BaseTool):
    """Universal vulnerability test tool — auto-selects the appropriate tester."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="vuln_test",
                description="Universal vulnerability test tool. Auto-selects the appropriate "
                "tester based on vuln_type. Supports: command_injection, sql_injection, "
                "xss, path_traversal, ssti, deserialization. Aliases: cmd, sqli, lfi, rfi, rce.",
                parameters={
                    "target_file": {
                        "type": "string",
                        "description": "Path to the file to test",
                    },
                    "vuln_type": {
                        "type": "string",
                        "description": "Vulnerability type: command_injection, sql_injection, xss, path_traversal, ssti, deserialization",
                    },
                    "param_name": {
                        "type": "string",
                        "description": "Parameter name to test (default: input)",
                    },
                    "payload": {
                        "type": "string",
                        "description": "Custom payload (optional)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: auto, php, python, javascript (default: auto)",
                    },
                },
                required=["target_file", "vuln_type"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        vuln_type = args.get("vuln_type", "").lower()
        vuln_type = VULN_TYPE_ALIASES.get(vuln_type, vuln_type)

        tool_map = {
            "command_injection": TestCommandInjectionTool(),
            "sql_injection": TestSqlInjectionTool(),
            "xss": TestXssTool(),
            "path_traversal": TestPathTraversalTool(),
            "ssti": TestSstiTool(),
            "deserialization": TestDeserializationTool(),
        }

        tool = tool_map.get(vuln_type)
        if not tool:
            return {
                "error": f"Unknown vulnerability type: {vuln_type}. "
                f"Supported: {', '.join(tool_map.keys())}",
                "vulnerable": False,
            }

        mapped_args = {"target_file": args["target_file"]}
        if "param_name" in args:
            mapped_args["param_name"] = args["param_name"]
        if "payload" in args:
            mapped_args["payload"] = args["payload"]
        if "language" in args:
            mapped_args["language"] = args["language"]

        return tool.execute(mapped_args, runtime_context)
