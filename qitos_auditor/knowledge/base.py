"""Base types for knowledge modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class KnowledgeDocument:
    """A single knowledge document for prompt injection.

    Unlike DeepAudit's ChromaDB-backed RAG system, QitOS stores
    knowledge as Python string constants and injects them directly
    into agent system prompts.
    """

    id: str
    title: str
    category: str  # "vulnerability" or "framework"
    tags: List[str] = field(default_factory=list)
    severity: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    owasp_ids: List[str] = field(default_factory=list)
    content: str = ""

    def to_prompt_section(self) -> str:
        """Format as a prompt section for injection."""
        header = f"## {self.title}"
        if self.cwe_ids:
            header += f" ({', '.join(self.cwe_ids)})"
        if self.severity:
            header += f" [Severity: {self.severity}]"
        return f"{header}\n\n{self.content}"
