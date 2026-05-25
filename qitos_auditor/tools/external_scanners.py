"""External security scanner tools — semgrep, bandit, gitleaks, npm audit, etc.

Each scanner wraps an external CLI tool, executing it either via Docker
sandbox or direct subprocess. Results are parsed and formatted for
agent consumption.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec


# ── Shared helpers ───────────────────────────────────────────────────

def _resolve_target(target_path: str, project_root: str) -> str:
    """Resolve a target path relative to project root.

    Handles '.', relative paths, and paths that include the project
    directory name as a subdirectory.
    """
    if target_path == ".":
        return project_root
    full = os.path.join(project_root, target_path)
    if os.path.exists(full):
        return full
    # If target includes project dir name as prefix, strip it
    proj_name = os.path.basename(project_root)
    if target_path.startswith(proj_name + "/") or target_path.startswith(proj_name + os.sep):
        return os.path.join(project_root, target_path[len(proj_name) + 1:])
    return project_root


def _run_command(
    cmd: str,
    timeout: int = 120,
    cwd: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a shell command and return structured result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout[:50000],
            "stderr": result.stderr[:5000],
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


def _docker_run(
    cmd: str,
    project_root: str,
    image: str = "python:3.11-slim",
    timeout: int = 120,
    network: str = "none",
) -> Dict[str, Any]:
    """Execute a command inside a Docker container with project mounted."""
    docker_cmd = (
        f"docker run --rm "
        f"--network={network} "
        f"-v {project_root}:/workspace:ro "
        f"-w /workspace "
        f"--memory=512m --cpus=1 "
        f"--cap-drop=ALL --security-opt=no-new-privileges "
        f"{image} "
        f"bash -c {repr(cmd)}"
    )
    return _run_command(docker_cmd, timeout=timeout)


def _try_docker_or_local(
    cmd: str,
    project_root: str,
    docker_image: str = "python:3.11-slim",
    timeout: int = 120,
    network: str = "none",
) -> Dict[str, Any]:
    """Try Docker execution first, fall back to local subprocess."""
    # Check if Docker is available
    docker_check = _run_command("docker ping 2>/dev/null || docker info >/dev/null 2>&1", timeout=10)
    if docker_check["exit_code"] == 0:
        result = _docker_run(cmd, project_root, docker_image, timeout, network)
        if result["exit_code"] != -1:
            return result

    # Fallback to local execution
    return _run_command(cmd, timeout=timeout, cwd=project_root)


def _extract_json(text: str) -> Any:
    """Try to extract JSON from text output."""
    # Try direct parse
    text = text.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Find first JSON object/array
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == start_char:
                    depth += 1
                elif text[i] == end_char:
                    depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    return None


# ── Semgrep ──────────────────────────────────────────────────────────

SEMGREP_RULESETS = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/r2c-security-audit",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/java",
    "p/go",
    "p/php",
    "p/ruby",
    "p/secrets",
    "p/sql-injection",
    "p/xss",
    "p/command-injection",
]


class SemgrepScanTool(BaseTool):
    """Semgrep static security analysis — supports 30+ languages."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="semgrep_scan",
                description="Semgrep static security analysis supporting 30+ languages. "
                "Use '.' for target_path to scan entire project. "
                f"Available rulesets: {', '.join(SEMGREP_RULESETS[:6])} and more.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "File or directory to scan. Use '.' for full project.",
                    },
                    "rules": {
                        "type": "string",
                        "description": "Semgrep ruleset config (default: p/security-audit)",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: ERROR, WARNING, INFO",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 50)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)
        rules = args.get("rules", "p/security-audit")
        severity = args.get("severity")
        max_results = int(args.get("max_results", 50))
        timeout = 300

        cmd = f"semgrep --json --quiet --config {rules}"
        if severity:
            cmd += f" --severity {severity}"
        cmd += f" {target}"

        result = _try_docker_or_local(
            cmd, project_root, timeout=timeout, network="bridge"
        )

        findings = []
        data = _extract_json(result.get("stdout", ""))
        if data and isinstance(data, dict):
            raw_findings = data.get("results", [])
            for f in raw_findings[:max_results]:
                sev = f.get("extra", {}).get("severity", "INFO")
                icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(sev, "⚪")
                findings.append({
                    "rule": f.get("check_id", ""),
                    "severity": sev,
                    "icon": icon,
                    "file": f.get("path", ""),
                    "line": f.get("start", {}).get("line", 0),
                    "message": f.get("extra", {}).get("message", ""),
                    "code": f.get("extra", {}).get("lines", ""),
                })

        return {
            "scanner": "semgrep",
            "findings_count": len(findings),
            "total_raw": len(data.get("results", [])) if data else 0,
            "findings": findings,
            "rules_used": rules,
            "raw_first_10": raw_findings[:10] if data else [],
        }


# ── Bandit ───────────────────────────────────────────────────────────

class BanditScanTool(BaseTool):
    """Bandit Python security scanner — shell/SQL injection, hardcoded passwords, etc."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="bandit_scan",
                description="Bandit Python security scanner detecting shell injection, "
                "SQL injection, hardcoded passwords, insecure deserialization, "
                "SSL/TLS issues. Python-specific.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory to scan. Use '.' for full project.",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Minimum severity: all, low, medium, high (default: medium)",
                    },
                    "confidence": {
                        "type": "string",
                        "description": "Minimum confidence: all, low, medium, high (default: medium)",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)
        severity = args.get("severity", "medium")
        confidence = args.get("confidence", "medium")
        max_results = int(args.get("max_results", 50))

        cmd = f"bandit -r -f json -l -i {target}"
        result = _try_docker_or_local(cmd, project_root, timeout=120)

        findings = []
        data = _extract_json(result.get("stdout", ""))
        if data and isinstance(data, dict):
            for f in data.get("results", [])[:max_results]:
                sev = f.get("issue_severity", "LOW")
                icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                findings.append({
                    "test_id": f.get("test_id", ""),
                    "severity": sev,
                    "icon": icon,
                    "confidence": f.get("issue_confidence", ""),
                    "file": f.get("filename", ""),
                    "line": f.get("line_number", 0),
                    "message": f.get("issue_text", ""),
                    "code": f.get("code", ""),
                })

        return {
            "scanner": "bandit",
            "findings_count": len(findings),
            "findings": findings,
        }


# ── Gitleaks ─────────────────────────────────────────────────────────

class GitleaksScanTool(BaseTool):
    """Gitleaks secret/credential detection — 150+ key types."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="gitleaks_scan",
                description="Gitleaks secret/credential leak detection supporting "
                "150+ key types (AWS, GCP, Azure, GitHub tokens, RSA keys, "
                "DB credentials, JWT secrets).",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory to scan. Use '.' for full project.",
                    },
                    "no_git": {
                        "type": "boolean",
                        "description": "Scan all files, not just git-tracked (default: true)",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results (default: 50)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)
        no_git = args.get("no_git", True)
        max_results = int(args.get("max_results", 50))

        no_git_flag = "--no-git" if no_git else ""
        import tempfile
        report_path = os.path.join(tempfile.gettempdir(), "gitleaks-report.json")
        cmd = (
            f"gitleaks detect --source {target} --report-format json "
            f"--report-path {report_path} --exit-code 0 "
            f"{no_git_flag} && cat {report_path}"
        )
        result = _try_docker_or_local(cmd, project_root, timeout=180)

        findings = []
        data = _extract_json(result.get("stdout", ""))
        if data and isinstance(data, list):
            for f in data[:max_results]:
                # Mask secrets for safety
                match_val = f.get("Match", "")
                if len(match_val) > 8:
                    match_val = match_val[:4] + "****" + match_val[-4:]
                findings.append({
                    "rule": f.get("RuleID", ""),
                    "file": f.get("File", ""),
                    "line": f.get("StartLine", 0),
                    "secret_type": f.get("RuleID", ""),
                    "match": match_val,
                })

        return {
            "scanner": "gitleaks",
            "findings_count": len(findings),
            "findings": findings,
        }


# ── npm audit ────────────────────────────────────────────────────────

class NpmAuditTool(BaseTool):
    """npm audit — Node.js dependency vulnerability scanner."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="npm_audit",
                description="Node.js dependency vulnerability scanner based on npm's "
                "official vulnerability database. Requires package.json.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory containing package.json. Use '.' for project root.",
                    },
                    "production_only": {
                        "type": "boolean",
                        "description": "Only audit production dependencies (default: false)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)
        production_only = args.get("production_only", False)

        # Check for package.json
        pkg_json = os.path.join(target, "package.json")
        if not os.path.exists(pkg_json):
            return {"scanner": "npm_audit", "error": "No package.json found", "findings": []}

        prod_flag = "--production" if production_only else ""
        cmd = f"cd {target} && npm audit --json {prod_flag}"
        result = _try_docker_or_local(
            cmd, project_root, timeout=120, network="bridge"
        )

        data = _extract_json(result.get("stdout", ""))
        findings = []
        if data and isinstance(data, dict):
            metadata = data.get("metadata", {})
            vulnerabilities = metadata.get("vulnerabilities", {})
            advisories = data.get("advisories", {})
            if isinstance(advisories, dict):
                for adv in advisories.values():
                    findings.append({
                        "title": adv.get("title", ""),
                        "severity": adv.get("severity", ""),
                        "package": adv.get("module_name", ""),
                        "version": adv.get("findings", [{}])[0].get("version", "") if adv.get("findings") else "",
                        "url": adv.get("url", ""),
                    })
            elif isinstance(advisories, list):
                for adv in advisories:
                    findings.append({
                        "title": adv.get("title", ""),
                        "severity": adv.get("severity", ""),
                        "package": adv.get("module_name", ""),
                    })

        return {
            "scanner": "npm_audit",
            "findings_count": len(findings),
            "vulnerabilities": vulnerabilities,
            "findings": findings,
        }


# ── Safety / pip-audit ───────────────────────────────────────────────

class SafetyCheckTool(BaseTool):
    """Safety/pip-audit — Python dependency vulnerability scanner."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="safety_check",
                description="Python dependency vulnerability scanner based on PyUp.io database. "
                "Supports requirements.txt, Pipfile.lock, poetry.lock.",
                parameters={
                    "requirements_file": {
                        "type": "string",
                        "description": "Path to requirements file (default: requirements.txt)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        req_file = args.get("requirements_file", "requirements.txt")
        req_path = os.path.join(project_root, req_file)

        if not os.path.exists(req_path):
            return {"scanner": "safety_check", "error": f"{req_file} not found", "findings": []}

        cmd = f"safety check -r {req_path} --json 2>/dev/null || pip-audit -r {req_path} --format json 2>/dev/null"
        result = _try_docker_or_local(cmd, project_root, timeout=120)

        data = _extract_json(result.get("stdout", ""))
        findings = []

        if data and isinstance(data, list):
            # Safety format: list of [name, version, id, description]
            for item in data:
                if isinstance(item, (list, tuple)) and len(item) >= 4:
                    findings.append({
                        "package": item[0],
                        "version": item[1],
                        "advisory_id": item[2],
                        "description": item[3],
                    })
        elif data and isinstance(data, dict):
            # pip-audit format
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    findings.append({
                        "package": dep.get("name", ""),
                        "version": dep.get("version", ""),
                        "advisory_id": vuln.get("id", ""),
                        "description": vuln.get("description", ""),
                        "fix_versions": vuln.get("fix_versions", []),
                    })

        return {
            "scanner": "safety_check",
            "findings_count": len(findings),
            "findings": findings,
        }


# ── TruffleHog ───────────────────────────────────────────────────────

class TruffleHogScanTool(BaseTool):
    """TruffleHog deep secret scanning — 700+ key types with verification."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="trufflehog_scan",
                description="Deep secret scanning supporting 700+ key types with "
                "verification capability. High precision, low false positives.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory to scan. Use '.' for full project.",
                    },
                    "only_verified": {
                        "type": "boolean",
                        "description": "Only return verified secrets (default: false)",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)
        only_verified = args.get("only_verified", False)

        verified_flag = "--only-verified" if only_verified else ""
        cmd = f"trufflehog filesystem {target} --json {verified_flag}"
        result = _try_docker_or_local(cmd, project_root, timeout=180)

        findings = []
        for line in result.get("stdout", "").strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                findings.append({
                    "detector": entry.get("DetectorType", 0),
                    "verified": entry.get("Verified", False),
                    "file": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("path", ""),
                    "line": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                })
            except json.JSONDecodeError:
                continue

        return {
            "scanner": "trufflehog",
            "findings_count": len(findings),
            "findings": findings[:50],
        }


# ── OSV-Scanner ──────────────────────────────────────────────────────

class OSVScannerTool(BaseTool):
    """OSV-Scanner — Google's open-source dependency vulnerability scanner."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="osv_scanner",
                description="Google's OSV-Scanner for open-source dependency vulnerabilities. "
                "Supports package.json, requirements.txt, go.mod, Cargo.lock, pom.xml, composer.lock.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory to scan. Use '.' for full project.",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)

        cmd = f"osv-scanner --json -r {target}"
        result = _try_docker_or_local(cmd, project_root, timeout=120)

        data = _extract_json(result.get("stdout", ""))
        findings = []

        if data and isinstance(data, dict):
            for pkg in data.get("results", []):
                source = pkg.get("source", {})
                for pkg_info in pkg.get("packages", []):
                    for vuln in pkg_info.get("vulnerabilities", []):
                        findings.append({
                            "package": pkg_info.get("package", {}).get("name", ""),
                            "version": pkg_info.get("package", {}).get("version", ""),
                            "osv_id": vuln.get("id", ""),
                            "summary": vuln.get("summary", ""),
                            "severity": vuln.get("database_specific", {}).get("severity", ""),
                            "source_path": source.get("path", ""),
                        })

        return {
            "scanner": "osv_scanner",
            "findings_count": len(findings),
            "findings": findings,
        }


# ── Kunlun-M ─────────────────────────────────────────────────────────

class KunlunScanTool(BaseTool):
    """Kunlun-M static analysis scanner."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="kunlun_scan",
                description="Kunlun-M static analysis scanner for code security audit.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory to scan. Use '.' for full project.",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)

        cmd = f"kunlun {target} -t 4 -o json"
        result = _try_docker_or_local(cmd, project_root, timeout=300)

        data = _extract_json(result.get("stdout", ""))
        findings = []
        if data and isinstance(data, dict):
            for item in data.get("result", [])[:50]:
                findings.append({
                    "vuln_type": item.get("vuln_class", ""),
                    "file": item.get("source", {}).get("file", ""),
                    "line": item.get("source", {}).get("line", 0),
                    "detail": item.get("detail", ""),
                })

        return {
            "scanner": "kunlun",
            "findings_count": len(findings),
            "findings": findings,
        }


class KunlunRuleListTool(BaseTool):
    """List available Kunlun-M analysis rules."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="kunlun_rule_list",
                description="List available Kunlun-M analysis rules and their descriptions.",
                parameters={
                    "category": {
                        "type": "string",
                        "description": "Filter rules by category (optional, e.g., 'xss', 'sqli', 'command_injection')",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        category = args.get("category", "")

        cmd = "kunlun --list-rules"
        if category:
            cmd += f" --category {category}"
        result = _try_docker_or_local(cmd, project_root, timeout=60)

        rules = []
        stdout = result.get("stdout", "")
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("Usage") and not line.startswith("Kunlun"):
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    rules.append({
                        "rule_id": parts[0],
                        "category": parts[1],
                        "description": parts[2] if len(parts) > 2 else "",
                    })

        return {
            "scanner": "kunlun",
            "rules_count": len(rules),
            "rules": rules[:100],
        }


class KunlunPluginTool(BaseTool):
    """Run a specific Kunlun-M plugin for targeted analysis."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="kunlun_plugin",
                description="Run a specific Kunlun-M plugin for targeted security analysis.",
                parameters={
                    "target_path": {
                        "type": "string",
                        "description": "Directory or file to analyze.",
                    },
                    "plugin_name": {
                        "type": "string",
                        "description": "Name of the Kunlun plugin to run (e.g., 'framework', 'crypto')",
                    },
                },
            )
        )

    def execute(
        self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        project_root = (runtime_context or {}).get("project_root", ".")
        target = _resolve_target(args.get("target_path", "."), project_root)
        plugin_name = args.get("plugin_name", "")

        if not plugin_name:
            return {"error": "plugin_name is required"}

        cmd = f"kunlun {target} -p {plugin_name} -o json"
        result = _try_docker_or_local(cmd, project_root, timeout=300)

        data = _extract_json(result.get("stdout", ""))
        findings = []
        if data and isinstance(data, dict):
            for item in data.get("result", [])[:50]:
                findings.append({
                    "vuln_type": item.get("vuln_class", ""),
                    "file": item.get("source", {}).get("file", ""),
                    "line": item.get("source", {}).get("line", 0),
                    "detail": item.get("detail", ""),
                    "plugin": plugin_name,
                })

        return {
            "scanner": "kunlun",
            "plugin": plugin_name,
            "findings_count": len(findings),
            "findings": findings,
        }


# ── Convenience: build all scanner tools ─────────────────────────────

def build_scanner_tools(config: Optional[Any] = None) -> List[BaseTool]:
    """Build all enabled external scanner tools based on config."""
    tools: List[BaseTool] = []
    # If config provided, check enable flags; otherwise include all
    if config is None or getattr(config, "enable_semgrep", True):
        tools.append(SemgrepScanTool())
    if config is None or getattr(config, "enable_bandit", True):
        tools.append(BanditScanTool())
    if config is None or getattr(config, "enable_gitleaks", True):
        tools.append(GitleaksScanTool())
    if config is None or getattr(config, "enable_npm_audit", True):
        tools.append(NpmAuditTool())
    if config is None or getattr(config, "enable_safety_check", True):
        tools.append(SafetyCheckTool())
    if config is None or getattr(config, "enable_trufflehog", False):
        tools.append(TruffleHogScanTool())
    if config is None or getattr(config, "enable_osv_scanner", True):
        tools.append(OSVScannerTool())
    if config is None or getattr(config, "enable_kunlun", False):
        tools.append(KunlunScanTool())
        tools.append(KunlunRuleListTool())
        tools.append(KunlunPluginTool())
    return tools
