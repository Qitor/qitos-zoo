"""Language-specific test tools — PHP, Python, JavaScript, Java, Go, Ruby, Shell."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


def _run_lang_command(cmd: list, timeout: int = 30, cwd: str = ".") -> Dict[str, Any]:
    """Execute a language-specific command."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {timeout}s"}
    except FileNotFoundError:
        return {"exit_code": -1, "stdout": "", "stderr": "Interpreter not found"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


def _analyze_output(output: str, params: Dict[str, str] = None) -> List[str]:
    """Detect vulnerability indicators in output."""
    indicators = []
    patterns = {
        "uid=": "command_execution",
        "root:": "file_access_passwd",
        "www-data": "web_user",
        "nobody:": "low_privilege_user",
        "daemon:": "daemon_user",
        "/bin/": "filesystem_access",
        "/etc/": "filesystem_access",
        "SQL syntax": "sql_error",
        "mysql": "mysql_error",
        "postgresql": "postgresql_error",
        "sqlite": "sqlite_error",
        "Traceback": "python_exception",
        "SyntaxError": "syntax_error",
        "stack traceback": "lua_error",
    }
    for pattern, label in patterns.items():
        if pattern.lower() in output.lower():
            indicators.append(label)

    # Check if param values appear in output (potential injection)
    if params:
        for val in params.values():
            if val in output and val not in ("id", "test", "input"):
                indicators.append(f"param_value_reflected")

    return indicators


# ── PHP Test ─────────────────────────────────────────────────────

class PhpTestTool(BaseTool):
    """Test PHP code in sandbox with simulated GET/POST parameters."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="php_test",
                description="Test PHP code in sandbox with simulated GET/POST parameters. "
                "Useful for verifying PHP injection vulnerabilities.",
                parameters={
                    "php_code": {
                        "type": "string",
                        "description": "PHP code to test (without <?php tags)",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "PHP file to test (alternative to php_code)",
                    },
                    "get_params": {
                        "type": "object",
                        "description": "Simulated $_GET parameters as key-value pairs",
                    },
                    "post_params": {
                        "type": "object",
                        "description": "Simulated $_POST parameters as key-value pairs",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("php_code", "")
        file_path = args.get("file_path")
        get_params = args.get("get_params", {})
        post_params = args.get("post_params", {})
        timeout = int(args.get("timeout", 30))

        if file_path and not code:
            full_path = os.path.join(project_root, file_path)
            if os.path.exists(full_path):
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    code = f.read()
            else:
                return {"error": f"File not found: {file_path}", "exit_code": -1}

        # Strip PHP tags
        code = re.sub(r"<\?php\s*", "", code)
        code = re.sub(r"<\?\s*", "", code)
        code = re.sub(r"\?>", "", code)

        # Prepend simulated superglobals
        wrapper = "error_reporting(E_ALL); "
        for key, val in get_params.items():
            wrapper += f"$_GET['{key}'] = '{val}'; "
        for key, val in post_params.items():
            wrapper += f"$_POST['{key}'] = '{val}'; "
        for key, val in {**get_params, **post_params}.items():
            wrapper += f"$_REQUEST['{key}'] = '{val}'; "

        full_code = wrapper + code
        result = _run_lang_command(["php", "-r", full_code], timeout=timeout, cwd=project_root)

        output = result.get("stdout", "") + result.get("stderr", "")
        indicators = _analyze_output(output, {**get_params, **post_params})

        return {
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:3000],
            "stderr": result.get("stderr", "")[:1000],
            "vulnerability_indicators": indicators,
        }


# ── Python Test ──────────────────────────────────────────────────

class PythonTestTool(BaseTool):
    """Test Python code with optional Flask/Django request mocking."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="python_test",
                description="Test Python code in sandbox with optional Flask/Django "
                "request mocking for vulnerability verification.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "Python code to test",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Python file to test (alternative to code)",
                    },
                    "params": {
                        "type": "object",
                        "description": "Parameters as key-value pairs",
                    },
                    "env_vars": {
                        "type": "object",
                        "description": "Environment variables as key-value pairs",
                    },
                    "flask_mode": {
                        "type": "boolean",
                        "description": "Enable Flask request mocking (default: false)",
                    },
                    "django_mode": {
                        "type": "boolean",
                        "description": "Enable Django request mocking (default: false)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        file_path = args.get("file_path")
        params = args.get("params", {})
        env_vars = args.get("env_vars", {})
        flask_mode = args.get("flask_mode", False)
        django_mode = args.get("django_mode", False)
        timeout = int(args.get("timeout", 30))

        if file_path and not code:
            full_path = os.path.join(project_root, file_path)
            if os.path.exists(full_path):
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    code = f.read()
            else:
                return {"error": f"File not found: {file_path}", "exit_code": -1}

        # Build wrapper
        wrapper = ""
        if flask_mode:
            wrapper = self._flask_mock(params)
        elif django_mode:
            wrapper = self._django_mock(params)
        else:
            wrapper = self._normal_mock(params, env_vars)

        full_code = wrapper + "\n" + code
        result = _run_lang_command(["python3", "-c", full_code], timeout=timeout, cwd=project_root)

        output = result.get("stdout", "") + result.get("stderr", "")
        indicators = _analyze_output(output, params)

        return {
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:3000],
            "stderr": result.get("stderr", "")[:1000],
            "vulnerability_indicators": indicators,
            "mode": "flask" if flask_mode else ("django" if django_mode else "normal"),
        }

    def _flask_mock(self, params: Dict[str, str]) -> str:
        """Build Flask request mock code."""
        mock = """
import sys; import os
class MockMultiDict(dict):
    def getlist(self, key): return [self.get(key, '')]
    def to_dict(self, flat=True): return dict(self)
class MockRequest:
    args = MockMultiDict(); form = MockMultiDict(); values = MockMultiDict()
    data = b''; json = None; method = 'GET'; path = '/'
    def get_json(self, **kw): return None
    def get_data(self, **kw): return b''
"""
        for k, v in params.items():
            mock += f"MockRequest.args['{k}'] = '{v}'; MockRequest.form['{k}'] = '{v}'; MockRequest.values['{k}'] = '{v}'\n"
        mock += "request = MockRequest()\n"
        mock += "import flask; sys.modules['flask'] = type('flask', (), {'request': request})()\n"
        return mock

    def _django_mock(self, params: Dict[str, str]) -> str:
        """Build Django request mock code."""
        mock = """
import sys; import os
class MockQueryDict(dict):
    def getlist(self, key): return [self.get(key, '')]
class MockRequest:
    GET = MockQueryDict(); POST = MockQueryDict()
    method = 'GET'; path = '/'; META = {}; body = b''
"""
        for k, v in params.items():
            mock += f"MockRequest.GET['{k}'] = '{v}'; MockRequest.POST['{k}'] = '{v}'\n"
        mock += "request = MockRequest()\n"
        return mock

    def _normal_mock(self, params: Dict[str, str], env_vars: Dict[str, str]) -> str:
        """Build normal execution mock code."""
        mock = "import sys; import os\n"
        if params:
            mock += f"sys.argv = ['test'] + {list(params.values())}\n"
        for k, v in env_vars.items():
            mock += f"os.environ['{k}'] = '{v}'\n"
        return mock


# ── JavaScript Test ──────────────────────────────────────────────

class JavaScriptTestTool(BaseTool):
    """Test JavaScript code with optional Express request mocking."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="javascript_test",
                description="Test JavaScript code in sandbox with optional Express "
                "request mocking for vulnerability verification.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "JavaScript code to test",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "JavaScript file to test (alternative to code)",
                    },
                    "params": {
                        "type": "object",
                        "description": "Parameters as key-value pairs",
                    },
                    "env_vars": {
                        "type": "object",
                        "description": "Environment variables as key-value pairs",
                    },
                    "express_mode": {
                        "type": "boolean",
                        "description": "Enable Express request mocking (default: false)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        file_path = args.get("file_path")
        params = args.get("params", {})
        express_mode = args.get("express_mode", False)
        timeout = int(args.get("timeout", 30))

        if file_path and not code:
            full_path = os.path.join(project_root, file_path)
            if os.path.exists(full_path):
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    code = f.read()
            else:
                return {"error": f"File not found: {file_path}", "exit_code": -1}

        if express_mode:
            mock = "const req = { query: {}, body: {}, params: {}, headers: {}, method: 'GET', path: '/', url: '/' };\n"
            mock += "const res = { send: (d) => console.log(d), json: (d) => console.log(JSON.stringify(d)), status: (c) => res, end: () => {} };\n"
            for k, v in params.items():
                mock += f"req.query['{k}'] = '{v}'; req.body['{k}'] = '{v}'; req.params['{k}'] = '{v}';\n"
            code = mock + code
        elif params:
            code = f"process.argv = ['node', 'test.js', ...{list(params.values())}];\n" + code

        result = _run_lang_command(["node", "-e", code], timeout=timeout, cwd=project_root)

        output = result.get("stdout", "") + result.get("stderr", "")
        indicators = _analyze_output(output, params)

        return {
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:3000],
            "stderr": result.get("stderr", "")[:1000],
            "vulnerability_indicators": indicators,
        }


# ── Java Test ────────────────────────────────────────────────────

class JavaTestTool(BaseTool):
    """Test Java code in sandbox."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="java_test",
                description="Test Java code in sandbox. Wraps code in a Test class "
                "with main method if needed.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "Java code to test",
                    },
                    "params": {
                        "type": "object",
                        "description": "Parameters as key-value pairs",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 60)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        params = args.get("params", {})
        timeout = int(args.get("timeout", 60))

        # Wrap in class if needed
        if "class " not in code or "public static void main" not in code:
            param_setup = ""
            for k, v in params.items():
                param_setup += f'        String {k} = "{v}";\n'
            code = f"""
import java.io.*; import java.util.*;
public class Test {{
    public static void main(String[] args) {{
{param_setup}
        {code}
    }}
}}"""

        # Write to temp file, compile, run
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".java", mode="w", delete=False, dir=project_root) as f:
            f.write(code)
            temp_path = f.name

        try:
            compile_result = _run_lang_command(["javac", temp_path], timeout=30, cwd=project_root)
            if compile_result["exit_code"] != 0:
                return {"exit_code": -1, "stderr": compile_result["stderr"][:2000], "phase": "compilation"}

            class_file = temp_path.replace(".java", ".class")
            run_result = _run_lang_command(["java", "-cp", project_root, "Test"], timeout=timeout, cwd=project_root)

            output = run_result.get("stdout", "") + run_result.get("stderr", "")
            indicators = _analyze_output(output, params)

            return {
                "exit_code": run_result.get("exit_code", -1),
                "stdout": run_result.get("stdout", "")[:3000],
                "stderr": run_result.get("stderr", "")[:1000],
                "vulnerability_indicators": indicators,
            }
        finally:
            for path in [temp_path, temp_path.replace(".java", ".class")]:
                if os.path.exists(path):
                    os.unlink(path)


# ── Go Test ──────────────────────────────────────────────────────

class GoTestTool(BaseTool):
    """Test Go code in sandbox."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="go_test",
                description="Test Go code in sandbox. Wraps code in package main "
                "with func main() if needed.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "Go code to test",
                    },
                    "params": {
                        "type": "object",
                        "description": "Parameters as key-value pairs",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 60)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        params = args.get("params", {})
        timeout = int(args.get("timeout", 60))

        # Wrap if needed
        if "package main" not in code:
            param_setup = ""
            for k, v in params.items():
                param_setup += f'    os.Setenv("{k}", "{v}")\n'
            code = f"""package main
import ("fmt"; "os"; "os/exec")
func main() {{
{param_setup}
    {code}
}}"""

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".go", mode="w", delete=False, dir=project_root) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = _run_lang_command(["go", "run", temp_path], timeout=timeout, cwd=project_root)
            output = result.get("stdout", "") + result.get("stderr", "")
            indicators = _analyze_output(output, params)

            return {
                "exit_code": result.get("exit_code", -1),
                "stdout": result.get("stdout", "")[:3000],
                "stderr": result.get("stderr", "")[:1000],
                "vulnerability_indicators": indicators,
            }
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


# ── Ruby Test ────────────────────────────────────────────────────

class RubyTestTool(BaseTool):
    """Test Ruby code with optional Rails request mocking."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="ruby_test",
                description="Test Ruby code in sandbox with optional Rails request mocking.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "Ruby code to test",
                    },
                    "params": {
                        "type": "object",
                        "description": "Parameters as key-value pairs",
                    },
                    "rails_mode": {
                        "type": "boolean",
                        "description": "Enable Rails request mocking (default: false)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        params = args.get("params", {})
        rails_mode = args.get("rails_mode", False)
        timeout = int(args.get("timeout", 30))

        if rails_mode:
            mock = "def params; {} end\n"
            for k, v in params.items():
                mock += f"params['{k}'] = '{v}'; "
            code = mock + "\n" + code
        elif params:
            for k, v in params.items():
                code = f"ARGV << '{v}'; ENV['{k}'] = '{v}';\n" + code

        result = _run_lang_command(["ruby", "-e", code], timeout=timeout, cwd=project_root)
        output = result.get("stdout", "") + result.get("stderr", "")
        indicators = _analyze_output(output, params)

        return {
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:3000],
            "stderr": result.get("stderr", "")[:1000],
            "vulnerability_indicators": indicators,
        }


# ── Shell Test ───────────────────────────────────────────────────

class ShellTestTool(BaseTool):
    """Test Shell/Bash code in sandbox."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="shell_test",
                description="Test Shell/Bash code in sandbox with environment variable injection.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "Shell code to test",
                    },
                    "params": {
                        "type": "object",
                        "description": "Environment variables to set as key-value pairs",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        params = args.get("params", {})
        timeout = int(args.get("timeout", 30))

        # Set environment variables from params
        env_setup = "#!/bin/bash\n"
        for k, v in params.items():
            env_setup += f"export {k}='{v}'\n"

        full_code = env_setup + code
        result = _run_lang_command(["bash", "-c", full_code], timeout=timeout, cwd=project_root)

        output = result.get("stdout", "") + result.get("stderr", "")
        indicators = _analyze_output(output, params)

        return {
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:3000],
            "stderr": result.get("stderr", "")[:1000],
            "vulnerability_indicators": indicators,
        }


# ── Universal Code Test ──────────────────────────────────────────

class CodeTestTool(BaseTool):
    """Universal multi-language code test tool — auto-selects the appropriate tester."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="code_test",
                description="Universal code test tool. Auto-selects the appropriate language "
                "tester. Supports: php, python, javascript, java, go, ruby, shell.",
                parameters={
                    "language": {
                        "type": "string",
                        "description": "Language: php, python, javascript, java, go, ruby, shell (required)",
                    },
                    "code": {
                        "type": "string",
                        "description": "Code to test",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "File to test (alternative to code)",
                    },
                    "params": {
                        "type": "object",
                        "description": "Parameters as key-value pairs",
                    },
                    "framework_mode": {
                        "type": "string",
                        "description": "Framework mode: flask, django, express, rails (optional)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
                required=["language"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        language = args.get("language", "").lower()
        # Aliases
        lang_aliases = {"js": "javascript", "node": "javascript", "golang": "go", "rb": "ruby", "bash": "shell"}
        language = lang_aliases.get(language, language)

        # Map framework_mode to tool-specific flags
        framework_mode = args.get("framework_mode", "")
        if framework_mode == "flask":
            args["flask_mode"] = True
        elif framework_mode == "django":
            args["django_mode"] = True
        elif framework_mode == "express":
            args["express_mode"] = True
        elif framework_mode == "rails":
            args["rails_mode"] = True

        tool_map = {
            "php": PhpTestTool(),
            "python": PythonTestTool(),
            "javascript": JavaScriptTestTool(),
            "java": JavaTestTool(),
            "go": GoTestTool(),
            "ruby": RubyTestTool(),
            "shell": ShellTestTool(),
        }

        tool = tool_map.get(language)
        if not tool:
            return {"error": f"Unsupported language: {language}. Supported: {', '.join(tool_map.keys())}"}

        return tool.execute(args, runtime_context)
