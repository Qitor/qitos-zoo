"""Root conftest for qitos-zoo — ensure standalone repo imports take precedence."""

import sys
from pathlib import Path

# Ensure this repo's qitos_zoo namespace is resolved before any other
# (e.g., the qitos repo's submodule at qitos/qitos_zoo/).
_repo_root = Path(__file__).resolve().parent

# Remove any qitos/qitos_zoo paths that may have been added by the qitos
# editable install's conftest.
sys.path = [
    p for p in sys.path
    if "qitos/qitos_zoo" not in p and "qitos\\qitos_zoo" not in p
]

# Ensure this repo root is on sys.path so `import qitos_zoo` resolves here.
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
