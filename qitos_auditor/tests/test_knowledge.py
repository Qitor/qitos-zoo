"""Tests for knowledge system."""

from qitos_zoo.qitos_auditor.knowledge import (
    KnowledgeDocument,
    KnowledgeLoader,
    knowledge_loader,
    ALL_KNOWLEDGE_DOCS,
    ALL_VULNERABILITY_DOCS,
    ALL_FRAMEWORK_DOCS,
    VULN_ALIASES,
    FRAMEWORK_ALIASES,
)


def test_all_knowledge_docs():
    assert len(ALL_VULNERABILITY_DOCS) == 21
    assert len(ALL_FRAMEWORK_DOCS) == 6
    assert len(ALL_KNOWLEDGE_DOCS) == 27


def test_knowledge_document():
    doc = KnowledgeDocument(
        id="test_doc",
        title="Test Doc",
        category="vulnerability",
        content="Test content",
        severity="high",
        cwe_ids=["CWE-89"],
    )
    section = doc.to_prompt_section()
    assert "Test Doc" in section
    assert "CWE-89" in section
    assert "[Severity: high]" in section


def test_loader_get_module():
    loader = KnowledgeLoader()
    # Direct ID
    doc = loader.get_module("vuln_sql_injection")
    assert doc is not None
    assert doc.id == "vuln_sql_injection"

    # Alias
    doc = loader.get_module("sqli")
    assert doc is not None
    assert doc.id == "vuln_sql_injection"

    # Framework
    doc = loader.get_module("flask")
    assert doc is not None
    assert doc.id == "framework_flask"


def test_loader_get_available_modules():
    loader = KnowledgeLoader()
    modules = loader.get_available_modules()
    assert len(modules) == 27
    assert "vuln_sql_injection" in modules
    assert "framework_flask" in modules


def test_loader_select_for_tech_stack():
    loader = KnowledgeLoader()
    # Python + Flask
    selected = loader.select_for_tech_stack({
        "language": "python",
        "framework": "flask",
    })
    assert len(selected) > 0
    # Should include Flask framework knowledge
    assert any(doc.id == "framework_flask" for doc in selected)
    # Should include must-include vulns
    assert any(doc.id == "vuln_sql_injection" for doc in selected)


def test_loader_build_prompt_section():
    loader = KnowledgeLoader()
    section = loader.build_prompt_section(tech_stack={"language": "python", "framework": "flask"})
    assert "专业安全知识参考" in section
    assert "SQL Injection" in section
    assert "Flask" in section


def test_loader_validate_modules():
    loader = KnowledgeLoader()
    result = loader.validate_modules(["sqli", "flask", "nonexistent"])
    assert result["sqli"] is True
    assert result["flask"] is True
    assert result["nonexistent"] is False


def test_vuln_aliases():
    assert "sqli" in VULN_ALIASES
    assert "rce" in VULN_ALIASES
    assert "lfi" in VULN_ALIASES
    assert VULN_ALIASES["sqli"] == "vuln_sql_injection"


def test_framework_aliases():
    assert "flask" in FRAMEWORK_ALIASES
    assert "express" in FRAMEWORK_ALIASES
    assert FRAMEWORK_ALIASES["flask"] == "framework_flask"


def test_knowledge_tools():
    from qitos_zoo.qitos_auditor.tools.knowledge_tools import (
        SecurityKnowledgeQueryTool,
        ListKnowledgeModulesTool,
        GetVulnerabilityKnowledgeTool,
    )

    # Test query
    query_tool = SecurityKnowledgeQueryTool()
    result = query_tool.execute({"query": "sql injection"})
    assert result["results_count"] > 0

    # Test list
    list_tool = ListKnowledgeModulesTool()
    result = list_tool.execute({})
    assert result["total_count"] == 27

    # Test get
    get_tool = GetVulnerabilityKnowledgeTool()
    result = get_tool.execute({"module_name": "sqli"})
    assert result["id"] == "vuln_sql_injection"

    # Test get with unknown module
    result = get_tool.execute({"module_name": "nonexistent"})
    assert "error" in result
