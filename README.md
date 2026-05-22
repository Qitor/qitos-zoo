# qitos_zoo

Applications and showcase agents built with QitOS.

QitOS core stays kernel-first and research-focused. This repository is for fuller applications that need their own prompts, configs, workflow state, tests, and release cadence.

## Apps

- **qitos_coder**: Claude Code-inspired coding agent — 30+ tools, permission pipeline, plan mode, sub-agents, streaming REPL
- **qitos_cyber**: PentAGI-inspired cybersecurity agent — 11 specialized agents, Docker execution, E2E evaluation framework
- **experimental**: migration candidates that need additional product hardening

## Import

```python
# After adding the project root to sys.path:
from qitos_zoo.qitos_coder import ClaudeCodeAgent, ClaudeCodeState
from qitos_zoo.qitos_cyber.pentagi import PentAGIRunner, PentAGIConfig
```

The project root (parent of `qitos_zoo/`) must be on `sys.path` for imports to work. This is handled automatically by test conftest files.

## Testing

Each app has its own `tests/` directory:

```bash
# qitos_coder E2E tests
python -m pytest qitos_zoo/qitos_coder/tests/test_e2e.py -m e2e -s

# qitos_cyber unit tests
python -m pytest qitos_zoo/qitos_cyber/tests/test_pentagi.py -x
```

## Safety

Security tooling in this repository is for controlled security research workflows, defensive evaluation, CTF-style sandboxes, and authorized environments only.

## Dependency Direction

qitos_zoo may depend on QitOS. QitOS must not depend on qitos_zoo.

## Directory Structure

```
qitos_zoo/
  __init__.py
  qitos_coder/          — Claude Code 风格 coding agent
    agent.py, system_prompt.py, cli.py, ...
    tests/
    README.md
  qitos_cyber/          — PentAGI 风格网络安全 agent
    pentagi/
    tests/
    README.md
  experimental/         — 待产品化的 agent 脚本
  docs/                 — 添加新 agent 指南、模板、安全规范
```
