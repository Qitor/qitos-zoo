"""Target manager — downloads and manages local code repositories for auditing."""

from __future__ import annotations

import logging
import os
import subprocess
from typing import Optional

from .targets import AuditTarget

logger = logging.getLogger(__name__)


class AuditTargetManager:
    """Manages download and lifecycle of source-code audit targets.

    Downloads GitHub repos to playground/<local_path> and provides
    ground-truth vulnerability data for scoring.
    """

    def __init__(self, target: AuditTarget, playground_root: str = "playground"):
        self.target = target
        self.playground_root = os.path.abspath(playground_root)
        self._target_path: Optional[str] = None

    def prepare(self) -> str:
        """Ensure the target code is available locally. Returns absolute path.

        For GitHub targets: clone (shallow) if not already present.
        For synthetic targets: return the dynamically-created path.
        """
        if self.target.repo_url:
            dest = os.path.join(self.playground_root, self.target.local_path)
            if os.path.isdir(os.path.join(dest, ".git")):
                logger.info(f"Target {self.target.name} already cloned at {dest}")
                self._target_path = dest
                return dest
            os.makedirs(self.playground_root, exist_ok=True)
            logger.info(f"Cloning {self.target.repo_url} -> {dest}")
            subprocess.run(
                ["git", "clone", "--depth", "1", self.target.repo_url, dest],
                check=True, capture_output=True, text=True, timeout=180,
            )
            self._target_path = dest
            return dest
        # Synthetic target
        if self.target.local_path:
            self._target_path = os.path.abspath(self.target.local_path)
            return self._target_path
        raise ValueError(f"Target {self.target.name} has no repo_url or local_path")

    def get_ground_truth(self) -> dict:
        """Return known vulnerability ground truth for scoring."""
        return {
            "vulnerabilities": dict(self.target.known_vulnerabilities),
            "languages": list(self.target.languages),
            "name": self.target.name,
        }

    def cleanup(self) -> None:
        """No-op. Repos persist across runs for speed."""
        pass

    @property
    def target_path(self) -> Optional[str]:
        return self._target_path
