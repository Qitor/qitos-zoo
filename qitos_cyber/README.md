# qitos_cyber

PentAGI 风格的网络安全 agent，基于 QitOS 框架构建。

## 安全声明

> 本应用仅用于受控安全研究、防御性评估、CTF 沙箱和授权环境。

## 功能特性

- 11 个专业 agent (Primary, Pentester, Coder, Installer, Searcher, Memorist, Generator, Refiner, Reporter, Adviser, Enricher)
- 35+ 工具 (Terminal, Browser, Search, Vector DB, Barrier, Delegate...)
- Docker 执行环境 (Kali, Ubuntu, Parrot)
- LLM 驱动的 Reflector 和 ToolCallFixer
- 向量数据库记忆
- E2E 评估框架 (4 级评分: Smoke, Reconnaissance, Vulnerability Discovery, Exploitation)
- 子任务管理与执行监控

## 快速开始

```bash
# 安装 qitos
pip install -e /path/to/qitos

# 编程方式使用
from qitos_zoo.qitos_cyber.pentagi import PentAGIRunner, PentAGIConfig

config = PentAGIConfig(
    model_provider="openai-compatible",
    model_name="qwen-plus",
    api_key="your-api-key",
    base_url="https://api.example.com/v1",
    docker_profile="kali",
    authorized_targets=["192.168.1.0/24"],
)

runner = PentAGIRunner(config)
result = runner.run("Penetration test against target.example.com")
```

## 目录结构

```
qitos_cyber/
  __init__.py                         — 公共 API
  pentagi/                            — 核心包
    agents/                           — 11 个专业 agent
    config/                           — PentAGIConfig + Docker profiles
    critic/                           — Reflector, StuckDetector, ToolCallFixer, Recovery
    e2e/                              — E2E 评估框架 (criteria, scorer, targets)
    memory/                           — PentAGIMemory + Vector DB
    orchestrator/                     — PentAGIFlow, SubtaskManager, ExecutionMonitor
    prompts/                          — 各 agent 系统提示词
    tools/                            — 35+ 工具
    runner.py                         — PentAGIRunner 入口
  code_security_audit_agent.py        — 代码安全审计 agent
  live_test_pentagi.py                — 实时集成测试
  tests/
    test_e2e.py                       — E2E 渗透测试效果测试
    test_e2e_scorer.py                — 评分器单元测试
    test_pentagi.py                   — 全面单元测试
  README.md                           — 本文件
```

## 测试

```bash
# 单元测试 (无需 API key)
cd /path/to/qitos
python -m pytest qitos_zoo/qitos_cyber/tests/test_pentagi.py -x
python -m pytest qitos_zoo/qitos_cyber/tests/test_e2e_scorer.py -x

# E2E 测试 (需要 API key + Docker)
export PENTAGI_API_KEY=xxx
python -m pytest qitos_zoo/qitos_cyber/tests/test_e2e.py -m e2e -s
```

## 依赖

- qitos >= 0.4.0
- openai (模型 provider)
- Docker (E2E 测试和目标环境)
