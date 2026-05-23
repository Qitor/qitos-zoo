"""Knowledge system for DeepAudit agents.

Unlike DeepAudit's ChromaDB-backed RAG, QitOS stores knowledge
as Python string constants and injects them directly into agent
system prompts via KnowledgeLoader.
"""

from .base import KnowledgeDocument
from .loader import KnowledgeLoader, knowledge_loader
from .vulnerability import ALL_VULNERABILITY_DOCS, VULN_ALIASES
from .framework import ALL_FRAMEWORK_DOCS, FRAMEWORK_ALIASES

ALL_KNOWLEDGE_DOCS = ALL_VULNERABILITY_DOCS + ALL_FRAMEWORK_DOCS

__all__ = [
    "KnowledgeDocument",
    "KnowledgeLoader",
    "knowledge_loader",
    "ALL_KNOWLEDGE_DOCS",
    "ALL_VULNERABILITY_DOCS",
    "ALL_FRAMEWORK_DOCS",
    "VULN_ALIASES",
    "FRAMEWORK_ALIASES",
]
