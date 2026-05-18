# qitos-zoo

Applications and showcase agents built with QitOS.

QitOS core stays kernel-first and research-focused. This repository is for fuller applications that need their own prompts, configs, workflow state, tests, and release cadence.

## Apps

- `apps/qitos-coder`: Claude Code-inspired coding agent built with QitOS.
- `apps/qitos-cyber-agent`: PentAGI-inspired cybersecurity agent built with QitOS.
- `apps/experimental`: migration candidates that need additional product hardening.

## Safety

Security tooling in this repository is for controlled security research workflows, defensive evaluation, CTF-style sandboxes, and authorized environments only.

## Dependency Direction

qitos-zoo may depend on QitOS. QitOS must not depend on qitos-zoo.
