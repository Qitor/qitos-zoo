"""FilePathValidationCritic — anti-hallucination guard for security audits.

Detects when an agent references file paths that haven't been read,
preventing fabricated findings about nonexistent files.
"""

from __future__ import annotations

from typing import Any, List, Optional, Set

from qitos.core.decision import Decision
from qitos.engine.critic import Critic
from qitos.engine.critic_result import CriticResult


class FilePathValidationCritic(Critic):
    """Anti-hallucination critic that validates file path references.

    Tracks which files an agent has read (via read_file tool calls)
    and flags any references to unread files in the agent's decisions.

    This is a critical safety measure — agents must not claim findings
    in files they haven't actually read.
    """

    def __init__(
        self,
        project_root: str = ".",
        max_warnings: int = 3,
    ):
        self._project_root = project_root
        self._max_warnings = max_warnings
        self._files_read: Set[str] = set()
        self._warning_count = 0

    def evaluate(
        self,
        state: Any,
        observation: Any,
        decision: Decision[Any],
    ) -> CriticResult:
        # Track files read from tool results
        self._track_reads(observation)

        # Check if decision references unread files
        referenced_files = self._extract_file_references(decision)
        unread_refs = referenced_files - self._files_read

        if unread_refs and self._warning_count < self._max_warnings:
            self._warning_count += 1
            return CriticResult(
                action="retry",
                reason=f"References to unread files detected: {unread_refs}. "
                f"You MUST read a file with read_file before referencing it in findings. "
                f"This is a critical anti-hallucination rule.",
                instruction_patch="Read the referenced files first, then update your findings.",
            )

        return CriticResult(action="continue")

    def _track_reads(self, observation: Any) -> None:
        """Track files that have been read via tool calls."""
        import os

        action_results = []
        if hasattr(observation, "action_results"):
            action_results = list(observation.action_results or [])
        elif isinstance(observation, dict):
            action_results = list(observation.get("action_results", []))

        for ar in action_results:
            output = getattr(ar, "output", None)
            if output is None and isinstance(ar, dict):
                output = ar.get("output", ar)
            if isinstance(output, dict):
                name = output.get("name", "")
                if name == "read_file":
                    path = output.get("file_path", output.get("path", ""))
                    if path:
                        self._files_read.add(path)

    def _extract_file_references(self, decision: Decision[Any]) -> Set[str]:
        """Extract file path references from decision text."""
        import re

        refs = set()

        # Handle case where decision might be a list instead of Decision object
        actions = []
        if hasattr(decision, "actions"):
            actions = decision.actions or []
        elif isinstance(decision, list):
            actions = decision

        # Check decision actions for file paths
        if actions:
            for action in actions:
                if hasattr(action, "args") and isinstance(action.args, dict):
                    for key in ("file_path", "target_file", "path"):
                        if key in action.args and action.args[key]:
                            refs.add(action.args[key])
        # Check thought text for file references
        if hasattr(decision, "thought") and decision.thought:
            # Look for common file path patterns
            for match in re.finditer(r'["\']?([\w/.-]+\.\w{1,10})["\']?', decision.thought):
                path = match.group(1)
                if "/" in path or path.startswith("."):
                    refs.add(path)
        return refs
