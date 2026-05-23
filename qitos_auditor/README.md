# qitos_auditor — Multi-Agent Code Security Audit

A QitOS-based multi-agent security audit system, faithfully replicating [DeepAudit](https://github.com/YiGuanZhiJia/DeepAudit) v3.0.4's core audit capabilities.

> **Security Notice**: This package performs automated security testing including sandboxed code execution, injection testing, and vulnerability scanning. It is intended **solely for authorized security assessment** of code you own or have explicit permission to test. Unauthorized use against systems you do not own is illegal and unethical. This package is **not** exported from the `qitos` namespace by default.

## Architecture

4 specialized agents collaborate in a phased pipeline:

```
Recon → Analysis → Verification → Report
   ↓         ↓           ↓
HandoffPayload (insights, findings, suggested actions passed between phases)
```

| Agent | Role | Step Budget |
|-------|------|-------------|
| **Orchestrator** | Coordinates phases, manages handoffs | 20 |
| **Recon** | Maps attack surface, detects tech stack | 15 |
| **Analysis** | Deep vulnerability hunting with 30+ tools | 30 |
| **Verification** | PoC validation, sandboxed exploitation | 25 |

## Quick Start

```python
from qitos_zoo.qitos_auditor import DeepAuditRunner, DeepAuditConfig

config = DeepAuditConfig(target_path="/path/to/project")
runner = DeepAuditRunner(config)
result = runner.run("Audit this codebase for security vulnerabilities")

print(result.report)              # Markdown report
print(result.summary)             # Executive summary
print(result.severity_counts)     # {"critical": 2, "high": 5, ...}
```

## Tools (40+)

### File Analysis
`read_file` · `smart_scan` · `pattern_match` · `code_analysis` · `extract_function` · `quick_audit` · `dataflow_analysis`

### External Scanners (Docker or local)
`semgrep_scan` · `bandit_scan` · `gitleaks_scan` · `npm_audit` · `safety_check` · `trufflehog_scan` · `osv_scanner` · `kunlun_scan`

### Injection Testing
`test_command_injection` · `test_sql_injection` · `test_xss` · `test_path_traversal` · `test_ssti` · `test_deserialization` · `vuln_test`

### Language-Specific Testing
`php_test` · `python_test` · `javascript_test` · `java_test` · `go_test` · `ruby_test` · `shell_test` · `code_test`

### Sandbox
`run_code` · `sandbox_exec` · `sandbox_http`

### Vulnerability & Knowledge
`vulnerability_validation` · `create_vulnerability_report` · `security_knowledge_query` · `list_knowledge_modules` · `get_vulnerability_knowledge`

## Knowledge System

27 built-in knowledge modules (no vector DB required):

- **21 vulnerability categories**: injection, XSS, SSRF, path traversal, deserialization, auth bypass, crypto weaknesses, XXE, race conditions, CSRF, business logic, open redirect, and more
- **6 framework guides**: Flask, Django, FastAPI, Express, React, Supabase

Knowledge is automatically injected into agent prompts based on the tech stack detected during Recon.

## Anti-Hallucination Safeguards

| Critic | Purpose |
|--------|---------|
| `FilePathValidationCritic` | Blocks findings referencing unread files |
| `RepeatedToolCallCritic` | Forces strategy change on repeated identical calls |
| `EmptyResponseCritic` | Retries empty LLM responses with guidance |
| `AuditProgressCritic` | Suggests direction changes when agent stagnates |
| `GracefulShutdownCritic` | Forces graceful completion before step budget exhaustion |

## Verification Verdicts

Each finding receives a verdict with confidence score:

| Verdict | Meaning |
|---------|---------|
| `confirmed` | PoC demonstrates the vulnerability |
| `likely` | Strong evidence but no working PoC |
| `uncertain` | Suspicious pattern, needs manual review |
| `false_positive` | Verified as not exploitable |

## Configuration

```python
config = DeepAuditConfig(
    target_path="/path/to/project",
    llm_provider="openai",        # or "anthropic", "local"
    model_name="gpt-4",
    max_steps=100,                # Total step budget across all phases
    docker_available=True,        # Enable Docker sandbox for scanners
    fast_mode=False,              # Skip verification phase
)
```

## Running Tests

```bash
# Unit tests
python -m pytest qitos_zoo/qitos_auditor/tests/ -v

# With core regression
python -m pytest tests/ -x -q --ignore=tests/test_model_providers.py
```
