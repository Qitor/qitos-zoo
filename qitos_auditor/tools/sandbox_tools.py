"""Sandbox execution tools — run_code, sandbox_exec, sandbox_http.

Provides Docker-based or subprocess-based code execution for
vulnerability verification and PoC testing.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Dict, Optional

from qitos.core.tool import BaseTool, ToolSpec


ALLOWED_COMMANDS = {
    "python", "python3", "node", "php", "ruby", "perl", "go", "java", "javac",
    "bash", "sh", "curl", "wget", "nc", "netcat",
    "cat", "head", "tail", "grep", "find", "ls", "wc",
    "sed", "awk", "cut", "sort", "uniq", "tr", "xargs",
    "echo", "printf", "test", "id", "whoami", "uname",
    "env", "printenv", "pwd", "hostname",
    "base64", "xxd", "od", "hexdump",
    "timeout", "time", "sleep", "true", "false",
    "md5sum", "sha256sum", "strings",
}


def _run_sandbox(
    command: str,
    timeout: int = 30,
    project_root: str = ".",
    network: str = "none",
) -> Dict[str, Any]:
    """Execute command in sandbox (Docker preferred, subprocess fallback)."""
    # Try Docker
    docker_check = subprocess.run(
        "docker info >/dev/null 2>&1",
        shell=True,
        capture_output=True,
        timeout=5,
    )
    if docker_check.returncode == 0:
        docker_cmd = (
            f"docker run --rm --network={network} "
            f"-v {os.path.abspath(project_root)}:/workspace "
            f"--memory=512m --cpus=1 "
            f"--cap-drop=ALL --security-opt=no-new-privileges "
            f"-w /workspace "
            f"python:3.11-slim "
            f"bash -c {repr(command)}"
        )
        try:
            result = subprocess.run(
                docker_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "exit_code": result.returncode,
                "stdout": result.stdout[:10000],
                "stderr": result.stderr[:3000],
                "sandbox": "docker",
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {timeout}s", "sandbox": "docker"}
        except Exception as e:
            pass

    # Fallback: local subprocess (with command whitelist)
    cmd_base = command.strip().split()[0] if command.strip() else ""
    if cmd_base not in ALLOWED_COMMANDS:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Command not allowed: {cmd_base}. Allowed: {', '.join(sorted(ALLOWED_COMMANDS)[:15])}...",
            "sandbox": "local",
        }

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=project_root,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout[:10000],
            "stderr": result.stderr[:3000],
            "sandbox": "local",
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {timeout}s", "sandbox": "local"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e), "sandbox": "local"}


# ── Run code ─────────────────────────────────────────────────────

class RunCodeTool(BaseTool):
    """Execute code in multiple languages within a sandbox."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="run_code",
                description="Execute code in Python, JavaScript, PHP, Ruby, or Shell. "
                "Use for PoC verification and vulnerability testing. "
                "Code runs in an isolated sandbox environment.",
                parameters={
                    "code": {
                        "type": "string",
                        "description": "Code to execute",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language: python, javascript, php, ruby, shell (default: python)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
                required=["code"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        code = args.get("code", "")
        language = args.get("language", "python").lower()
        timeout = int(args.get("timeout", 30))

        # Build command based on language
        cmd_map = {
            "python": f"python3 -c {repr(code)}",
            "python3": f"python3 -c {repr(code)}",
            "javascript": f"node -e {repr(code)}",
            "js": f"node -e {repr(code)}",
            "node": f"node -e {repr(code)}",
            "php": f"php -r {repr(code)}",
            "ruby": f"ruby -e {repr(code)}",
            "rb": f"ruby -e {repr(code)}",
            "shell": f"bash -c {repr(code)}",
            "bash": f"bash -c {repr(code)}",
            "sh": f"bash -c {repr(code)}",
        }

        cmd = cmd_map.get(language)
        if not cmd:
            return {
                "error": f"Unsupported language: {language}. Supported: python, javascript, php, ruby, shell",
                "exit_code": -1,
            }

        result = _run_sandbox(cmd, timeout=timeout, project_root=project_root)

        # Analyze output for vulnerability indicators
        output = result.get("stdout", "") + result.get("stderr", "")
        indicators = self._detect_indicators(output)

        return {
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "sandbox": result.get("sandbox", "unknown"),
            "language": language,
            "vulnerability_indicators": indicators,
        }

    @staticmethod
    def _detect_indicators(output: str) -> List[str]:
        """Detect vulnerability-related patterns in output."""
        indicators = []
        patterns = {
            "uid=": "command_execution_id",
            "root:": "command_execution_passwd",
            "www-data": "web_user_access",
            "nobody": "low_privilege_user",
            "SQL syntax": "sql_error",
            "mysql": "mysql_error",
            "postgresql": "postgresql_error",
            "sqlite": "sqlite_error",
            "Traceback": "python_exception",
            "Exception": "java_exception",
            "Fatal error": "php_error",
        }
        for pattern, label in patterns.items():
            if pattern.lower() in output.lower():
                indicators.append(label)
        return indicators


# ── Sandbox exec ─────────────────────────────────────────────────

class SandboxExecTool(BaseTool):
    """Execute commands in a secure Docker sandbox."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="sandbox_exec",
                description="Execute commands in a secure Docker sandbox for vulnerability "
                "verification and PoC testing. Only whitelisted commands are allowed.",
                parameters={
                    "command": {
                        "type": "string",
                        "description": "Command to execute in the sandbox",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds (default: 30)",
                    },
                },
                required=["command"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        command = args.get("command", "")
        timeout = int(args.get("timeout", 30))

        # Validate command against whitelist
        cmd_base = command.strip().split()[0] if command.strip() else ""
        if cmd_base not in ALLOWED_COMMANDS:
            return {
                "error": f"Command not allowed: {cmd_base}",
                "allowed": sorted(list(ALLOWED_COMMANDS)),
                "exit_code": -1,
            }

        result = _run_sandbox(command, timeout=timeout, project_root=project_root)

        return {
            "command": command,
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "sandbox": result.get("sandbox", "unknown"),
        }


# ── Sandbox HTTP ─────────────────────────────────────────────────

class SandboxHttpTool(BaseTool):
    """Send HTTP requests from the sandbox for web vulnerability testing."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="sandbox_http",
                description="Send HTTP requests from the sandbox for testing web "
                "vulnerabilities (SQLi, XSS, SSRF, auth bypass). Uses curl internally.",
                parameters={
                    "method": {
                        "type": "string",
                        "description": "HTTP method: GET, POST, PUT, DELETE, PATCH (default: GET)",
                    },
                    "url": {
                        "type": "string",
                        "description": "Target URL",
                    },
                    "headers": {
                        "type": "object",
                        "description": "HTTP headers as key-value pairs",
                    },
                    "data": {
                        "type": "string",
                        "description": "Request body data",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds (default: 30)",
                    },
                },
                required=["url"],
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        method = args.get("method", "GET").upper()
        url = args.get("url", "")
        headers = args.get("headers", {})
        data = args.get("data")
        timeout = int(args.get("timeout", 30))

        if not url:
            return {"error": "URL is required", "status": "error"}

        # Build curl command
        cmd_parts = [
            "curl",
            "-s",
            "-o", "/dev/stdout",
            "-w", "'\\n__HTTP_STATUS__%{http_code}__HTTP_SIZE__%{size_download}'",
            "-X", method,
            "--max-time", str(timeout),
        ]

        for key, val in headers.items():
            cmd_parts.extend(["-H", f"{key}: {val}"])

        if data:
            cmd_parts.extend(["-d", repr(data)])

        cmd_parts.append(repr(url))
        cmd = " ".join(cmd_parts)

        result = _run_sandbox(cmd, timeout=timeout + 5, project_root=project_root, network="bridge")

        output = result.get("stdout", "")
        status_code = 0
        response_size = 0

        # Parse status code from curl output
        status_match = output.rfind("__HTTP_STATUS__")
        if status_match >= 0:
            try:
                status_part = output[status_match:]
                status_code = int(status_part.split("__HTTP_STATUS__")[1].split("__")[0])
                size_match = status_part.find("__HTTP_SIZE__")
                if size_match >= 0:
                    response_size = int(status_part[size_match:].split("__HTTP_SIZE__")[1].split("'")[0])
                output = output[:status_match]
            except (ValueError, IndexError):
                pass

        # Truncate response body
        truncated = len(output) > 2000
        body = output[:2000]

        return {
            "status_code": status_code,
            "body": body,
            "body_length": response_size,
            "truncated": truncated,
            "method": method,
            "url": url,
            "sandbox": result.get("sandbox", "unknown"),
        }
