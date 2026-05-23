"""DeepAudit tools — all security audit tools for the multi-agent system."""

from .barrier import AuditDone, ReconResult, AnalysisResult, VerificationResult
from .file_tools import ReadFileTool, SmartScanTool, PatternMatchTool, CodeAnalysisTool, ExtractFunctionTool, QuickAuditTool
from .external_scanners import (
    SemgrepScanTool, BanditScanTool, GitleaksScanTool, NpmAuditTool,
    SafetyCheckTool, TruffleHogScanTool, OSVScannerTool, KunlunScanTool,
    KunlunRuleListTool, KunlunPluginTool,
    build_scanner_tools,
)
from .dataflow import DataflowAnalysisTool
from .vuln_tools import VulnerabilityValidationTool, CreateVulnerabilityReportTool
from .sandbox_tools import RunCodeTool, SandboxExecTool, SandboxHttpTool
from .injection_tests import (
    TestCommandInjectionTool, TestSqlInjectionTool, TestXssTool,
    TestPathTraversalTool, TestSstiTool, TestDeserializationTool, VulnTestTool,
)
from .language_tests import (
    PhpTestTool, PythonTestTool, JavaScriptTestTool, JavaTestTool,
    GoTestTool, RubyTestTool, ShellTestTool, CodeTestTool,
)
from .knowledge_tools import (
    SecurityKnowledgeQueryTool, ListKnowledgeModulesTool, GetVulnerabilityKnowledgeTool,
)
from .thinking import ThinkTool, ReflectTool
from .delegate import (
    DelegateToReconTool, DelegateToAnalysisTool, DelegateToVerificationTool,
    build_audit_delegate_tools,
)

__all__ = [
    # Barrier
    "AuditDone", "ReconResult", "AnalysisResult", "VerificationResult",
    # File tools
    "ReadFileTool", "SmartScanTool", "PatternMatchTool", "CodeAnalysisTool",
    "ExtractFunctionTool", "QuickAuditTool",
    # External scanners
    "SemgrepScanTool", "BanditScanTool", "GitleaksScanTool", "NpmAuditTool",
    "SafetyCheckTool", "TruffleHogScanTool", "OSVScannerTool", "KunlunScanTool",
    "KunlunRuleListTool", "KunlunPluginTool",
    "build_scanner_tools",
    # Dataflow
    "DataflowAnalysisTool",
    # Vuln tools
    "VulnerabilityValidationTool", "CreateVulnerabilityReportTool",
    # Sandbox
    "RunCodeTool", "SandboxExecTool", "SandboxHttpTool",
    # Injection tests
    "TestCommandInjectionTool", "TestSqlInjectionTool", "TestXssTool",
    "TestPathTraversalTool", "TestSstiTool", "TestDeserializationTool", "VulnTestTool",
    # Language tests
    "PhpTestTool", "PythonTestTool", "JavaScriptTestTool", "JavaTestTool",
    "GoTestTool", "RubyTestTool", "ShellTestTool", "CodeTestTool",
    # Knowledge
    "SecurityKnowledgeQueryTool", "ListKnowledgeModulesTool", "GetVulnerabilityKnowledgeTool",
    # Delegate
    "DelegateToReconTool", "DelegateToAnalysisTool", "DelegateToVerificationTool",
    "build_audit_delegate_tools",
    # Thinking
    "ThinkTool", "ReflectTool",
]
