"""Knowledge query tools — security_knowledge_query, list_knowledge_modules, get_vulnerability_knowledge."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from qitos.core.tool import BaseTool, ToolSpec

from ..knowledge.loader import knowledge_loader


class SecurityKnowledgeQueryTool(BaseTool):
    """Query security knowledge by keyword or vulnerability type."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="security_knowledge_query",
                description="Query security knowledge by keyword or vulnerability type. "
                "Returns relevant vulnerability patterns, detection methods, and fix examples.",
                parameters={
                    "query": {
                        "type": "string",
                        "description": "Search query — vulnerability type, keyword, or concept",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Maximum number of results (default: 3)",
                    },
                },
                required=["query"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = args.get("query", "").lower()
        top_k = int(args.get("top_k", 3))

        # Simple keyword matching across all knowledge docs
        results = []
        for doc in knowledge_loader._all_docs.values():
            score = 0
            query_terms = query.split()

            # Check ID/title/tags match
            for term in query_terms:
                if term in doc.id.lower():
                    score += 3
                if term in doc.title.lower():
                    score += 2
                for tag in doc.tags:
                    if term in tag.lower():
                        score += 1
                if term in doc.content.lower():
                    score += 0.5

            if score > 0:
                results.append((score, doc))

        # Sort by score descending
        results.sort(key=lambda x: x[0], reverse=True)

        # Return top-k formatted results
        formatted = []
        for score, doc in results[:top_k]:
            formatted.append({
                "id": doc.id,
                "title": doc.title,
                "category": doc.category,
                "severity": doc.severity,
                "cwe_ids": doc.cwe_ids,
                "tags": doc.tags,
                "content_preview": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content,
            })

        return {
            "query": query,
            "results_count": len(formatted),
            "results": formatted,
        }


class ListKnowledgeModulesTool(BaseTool):
    """List all available security knowledge modules."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="list_knowledge_modules",
                description="List all available security knowledge modules. "
                "Use this to discover what vulnerability types and frameworks "
                "have dedicated knowledge available.",
                parameters={},
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        vuln_modules = []
        for doc_id, doc in knowledge_loader._vuln_docs.items():
            vuln_modules.append({
                "id": doc.id,
                "title": doc.title,
                "severity": doc.severity,
                "cwe_ids": doc.cwe_ids,
                "tags": doc.tags,
            })

        fw_modules = []
        for doc_id, doc in knowledge_loader._fw_docs.items():
            fw_modules.append({
                "id": doc.id,
                "title": doc.title,
                "tags": doc.tags,
            })

        return {
            "vulnerability_modules": vuln_modules,
            "framework_modules": fw_modules,
            "total_count": len(vuln_modules) + len(fw_modules),
        }


class GetVulnerabilityKnowledgeTool(BaseTool):
    """Get detailed knowledge for a specific vulnerability type."""

    def __init__(self):
        super().__init__(
            ToolSpec(
                name="get_vulnerability_knowledge",
                description="Get detailed security knowledge for a specific vulnerability type "
                "or framework. Returns patterns, detection methods, and fix examples.",
                parameters={
                    "module_name": {
                        "type": "string",
                        "description": "Module name or alias (e.g., sql_injection, sqli, xss, flask, django)",
                    },
                },
                required=["module_name"],
            )
        )

    def execute(self, args: Dict[str, Any], runtime_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        module_name = args.get("module_name", "")

        doc = knowledge_loader.get_module(module_name)
        if doc is None:
            available = knowledge_loader.get_available_modules()
            return {
                "error": f"Module not found: {module_name}",
                "available_modules": available[:20],
                "hint": "Use list_knowledge_modules to see all available modules",
            }

        return {
            "id": doc.id,
            "title": doc.title,
            "category": doc.category,
            "severity": doc.severity,
            "cwe_ids": doc.cwe_ids,
            "owasp_ids": doc.owasp_ids,
            "tags": doc.tags,
            "content": doc.content,
        }
