# Contributing to qitos-zoo

Thank you for your interest in contributing to the QitOS Zoo!

## Relationship with QitOS

qitos-zoo is the official agent reproduction zoo for the [QitOS](https://github.com/Qitor/qitos) agent framework. It depends on qitos through public APIs only.

**Key rules:**
- qitos-zoo must only import from `qitos` public APIs.
- Do not import from private `qitos._*` submodules.
- Each reproduced agent should be self-contained with its own directory, README, and tests.
- Do not modify qitos core behavior from zoo code.

## Getting Started

1. Fork and clone the repository
2. Install qitos: `pip install "qitos[models]"`
3. Install qitos-zoo in development mode: `pip install -e .`
4. Run tests for a specific app: `python -m pytest qitos_cyber/tests/ -q`

## Adding a New Agent

See [docs/adding_a_new_agent.md](./docs/adding_a_new_agent.md) for the step-by-step guide.

Each agent should include:
- A clear directory with `__init__.py`
- Agent implementation code
- A README with usage instructions
- Tests that do not require secrets or external services by default
- An `eval_config.yaml` if the agent supports evaluation

## Development Workflow

1. Create a feature branch from `main`
2. Implement your agent following the standard structure
3. Ensure tests pass for your app
4. Open a pull request

## Quality Bar

- Agents must not require API keys or secrets by default
- Heavy assets, models, and datasets must not be committed
- Each agent must have a README explaining what it reproduces and how to run it
