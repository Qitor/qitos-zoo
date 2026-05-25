# Changelog

This project keeps a human-curated changelog so users and contributors can see how qitos-zoo evolves over time.

Format:
- `Added`: new features and capabilities
- `Changed`: behavior changes, refactors, and structural improvements
- `Fixed`: bug fixes
- `Deprecated`: old paths or APIs that will be removed later
- `Removed`: deleted features
- `Breaking`: upgrade notes for incompatible changes

## Unreleased

### Added

- `pyproject.toml` for proper packaging and installation.
- CONTRIBUTING.md, SECURITY.md, and this CHANGELOG.md.
- CI workflow for automated testing.
- eval_config.yaml and snowl_compat.py for each app.

### Fixed

- Replaced hardcoded `/tmp` paths in `qitos_auditor/tools/external_scanners.py` with `tempfile`-based paths.
- Use public `qitos.engine.ToolCallLoopDetector` instead of private `_loop_detector` import.
- Removed hardcoded `/Users/morinop/` paths from conftest files.
