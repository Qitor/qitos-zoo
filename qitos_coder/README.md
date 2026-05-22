# qitos_coder

Claude Code 风格的 coding agent，基于 QitOS 框架构建。

## 功能特性

- 30+ 工具 (Read, Edit, Write, Glob, Grep, Bash, Agent, LSP...)
- 多层权限管道 (default / plan / acceptEdits / bypassPermissions / auto)
- Read-before-write 强制
- Plan mode (只读模式，禁止写入)
- 子 agent 系统 (explore / plan / general-purpose)
- AutoPermissionClassifier 自动权限分类
- 流式输出 + REPL
- 项目指令 (.qitos/instructions.md)
- Git 感知 (diff/status 注入上下文)

## 快速开始

```bash
# 安装 qitos
pip install -e /path/to/qitos

# 设置 API
export OPENAI_API_KEY=your-key
export OPENAI_BASE_URL=https://api.example.com/v1

# 交互模式
python -m qitos_zoo.qitos_coder --workspace . --model ds-v4-pro --repl

# 单任务模式
python -m qitos_zoo.qitos_coder --workspace . --model ds-v4-pro -t "Fix the bug in main.py"

# Bypass 权限模式 (无需确认)
python -m qitos_zoo.qitos_coder --workspace . --model ds-v4-pro --permission-mode bypassPermissions -t "Read README.md"
```

## 目录结构

```
qitos_coder/
  __init__.py           — 公共 API (ClaudeCodeAgent, ClaudeCodeState, main)
  __main__.py           — python -m 入口
  agent.py              — ClaudeCodeAgent 定义
  system_prompt.py      — 7 节系统提示词
  cli.py                — CLI 入口 (argparse + AgentREPL)
  preset_agent.py       — 最小化 preset-first 示例
  diff.md               — 与真实 Claude Code 的差距分析
  README.md             — 本文件
  tests/
    __init__.py
    conftest.py          — 测试 sys.path 配置
    test_e2e.py          — E2E 功能测试 (需要 LLM API)
    run_e2e.py           — 独立 E2E 测试运行器
```

## 测试

```bash
# 运行核心测试 (无需 API key)
cd /path/to/qitos
python -m pytest tests/test_claude_code_streaming.py -x

# 运行 E2E 测试 (需要 API key)
export OPENAI_API_KEY=xxx
export OPENAI_BASE_URL=xxx
python -m pytest qitos_zoo/qitos_coder/tests/test_e2e.py -m e2e -s

# 或使用独立运行器
python qitos_zoo/qitos_coder/tests/run_e2e.py
```

## 依赖

- qitos >= 0.4.0
- openai (模型 provider)

## 与真实 Claude Code 的差距

详见 [diff.md](diff.md)，涵盖 6 个维度的差距分析：
1. 引擎架构 (流式、并发、上下文管理)
2. REPL/UX 体验
3. 工具与能力
4. 优先级路线图
