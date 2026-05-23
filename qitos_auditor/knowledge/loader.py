"""KnowledgeLoader — selects and formats knowledge for prompt injection.

Selects relevant knowledge modules based on tech stack detected
during the Recon phase, then formats them for injection into
agent system prompts.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from .base import KnowledgeDocument
from .vulnerability import ALL_VULNERABILITY_DOCS, VULN_ALIASES
from .framework import ALL_FRAMEWORK_DOCS, FRAMEWORK_ALIASES


class KnowledgeLoader:
    """Select and format knowledge modules for prompt injection.

    This replaces DeepAudit's ChromaDB RAG with simple Python
    string constants. Knowledge is injected directly into agent
    system prompts based on detected tech stack.
    """

    def __init__(self):
        self._vuln_docs: Dict[str, KnowledgeDocument] = {
            doc.id: doc for doc in ALL_VULNERABILITY_DOCS
        }
        self._fw_docs: Dict[str, KnowledgeDocument] = {
            doc.id: doc for doc in ALL_FRAMEWORK_DOCS
        }
        self._all_docs = {**self._vuln_docs, **self._fw_docs}

    # ── Module lookup ─────────────────────────────────────────────

    def get_module(self, name: str) -> Optional[KnowledgeDocument]:
        """Look up a knowledge module by ID or alias."""
        # Direct ID match
        if name in self._all_docs:
            return self._all_docs[name]

        # Alias resolution — try vulnerability aliases
        normalized = name.lower().replace("-", "_")
        if normalized in VULN_ALIASES:
            return self._all_docs.get(VULN_ALIASES[normalized])
        if normalized in FRAMEWORK_ALIASES:
            return self._all_docs.get(FRAMEWORK_ALIASES[normalized])

        # Fuzzy: check if name is a substring of any doc ID
        for doc_id, doc in self._all_docs.items():
            if normalized in doc_id.replace("-", "_"):
                return doc

        return None

    def get_available_modules(self) -> List[str]:
        """Return all available module IDs."""
        return list(self._all_docs.keys())

    def get_vulnerability_types(self) -> List[str]:
        """Return all vulnerability module IDs."""
        return list(self._vuln_docs.keys())

    def get_framework_types(self) -> List[str]:
        """Return all framework module IDs."""
        return list(self._fw_docs.keys())

    # ── Tech-stack-based selection ────────────────────────────────

    def select_for_tech_stack(self, tech_stack: Dict[str, str]) -> List[KnowledgeDocument]:
        """Select relevant knowledge modules based on detected tech stack.

        Parameters
        ----------
        tech_stack : dict
            Keys like "language", "framework", "database", "runtime".
            Values are lowercase identifiers, e.g. "python", "flask".
        """
        selected: List[KnowledgeDocument] = []
        seen_ids: Set[str] = set()

        # Always include top-priority vulnerability knowledge
        must_include = [
            "vuln_sql_injection",
            "vuln_command_injection",
            "vuln_code_injection",
            "vuln_path_traversal",
            "vuln_xss_reflected",
            "vuln_hardcoded_secrets",
        ]
        for doc_id in must_include:
            if doc_id in self._vuln_docs and doc_id not in seen_ids:
                selected.append(self._vuln_docs[doc_id])
                seen_ids.add(doc_id)

        # Framework-specific knowledge
        framework = tech_stack.get("framework", "").lower()
        language = tech_stack.get("language", "").lower()
        runtime = tech_stack.get("runtime", "").lower()

        fw_keywords = [framework, runtime]
        if language == "python":
            fw_keywords.extend(["flask", "django", "fastapi"])
        elif language in ("javascript", "typescript"):
            fw_keywords.extend(["express", "react", "node"])
        elif language == "java":
            fw_keywords.append("spring")
        elif language == "go":
            fw_keywords.append("go")

        for kw in fw_keywords:
            if not kw:
                continue
            for doc in ALL_FRAMEWORK_DOCS:
                if doc.id in seen_ids:
                    continue
                if kw in doc.tags or kw in doc.id:
                    selected.append(doc)
                    seen_ids.add(doc.id)

        # Database-specific vulnerability knowledge
        database = tech_stack.get("database", "").lower()
        if database in ("mongodb", "nosql"):
            doc = self._vuln_docs.get("vuln_nosql_injection")
            if doc and doc.id not in seen_ids:
                selected.append(doc)
                seen_ids.add(doc.id)

        # If framework is Flask, add SSTI knowledge
        if framework == "flask":
            doc = self._vuln_docs.get("vuln_code_injection")
            if doc and doc.id not in seen_ids:
                selected.append(doc)
                seen_ids.add(doc.id)

        return selected

    # ── Prompt formatting ─────────────────────────────────────────

    def build_prompt_section(
        self,
        modules: Optional[List[KnowledgeDocument]] = None,
        tech_stack: Optional[Dict[str, str]] = None,
    ) -> str:
        """Build a knowledge prompt section for injection.

        Either provide modules directly, or provide tech_stack
        for automatic selection.
        """
        if modules is None:
            if tech_stack is None:
                tech_stack = {}
            modules = self.select_for_tech_stack(tech_stack)

        if not modules:
            return ""

        parts = [
            "---",
            "## 专业安全知识参考",
            "以下是与当前任务相关的安全知识，请在分析时参考：",
            "",
        ]
        for doc in modules:
            parts.append(doc.to_prompt_section())
            parts.append("")

        parts.append("---")
        return "\n".join(parts)

    def validate_modules(self, names: List[str]) -> Dict[str, bool]:
        """Check which module names are valid (exist or resolve via alias)."""
        result = {}
        for name in names:
            result[name] = self.get_module(name) is not None
        return result


# Module-level singleton
knowledge_loader = KnowledgeLoader()
