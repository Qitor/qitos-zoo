"""Conftest for qitos_coder tests — ensures qitos and qitos_zoo are importable."""

import sys
from pathlib import Path

# Project root (contains both qitos/ and qitos_zoo/)
_project_root = str(Path(__file__).resolve().parents[3])
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
