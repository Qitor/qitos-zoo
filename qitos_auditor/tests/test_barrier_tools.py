"""Tests for barrier tools."""

from qitos_zoo.qitos_auditor.tools.barrier import (
    AuditDone, ReconResult, AnalysisResult, VerificationResult,
    _build_handoff_payload,
)


def test_audit_done():
    tool = AuditDone()
    assert tool.spec.name == "done"
    result = tool.execute({"summary": "Audit complete", "findings_count": 5, "critical_count": 2})
    assert result["status"] == "done"
    assert result["findings_count"] == 5
    assert result["critical_count"] == 2


def test_recon_result():
    tool = ReconResult()
    assert tool.spec.name == "recon_result"
    result = tool.execute({
        "summary": "Flask app detected",
        "key_findings": ["Python Flask web application"],
        "suggested_actions": ["Run bandit_scan"],
        "context_data": {"tech_stack": {"language": "python", "framework": "flask"}},
        "confidence": 0.85,
    })
    assert result["phase"] == "recon"
    assert result["summary"] == "Flask app detected"
    assert result["confidence"] == 0.85


def test_analysis_result():
    tool = AnalysisResult()
    assert tool.spec.name == "analysis_result"
    result = tool.execute({
        "summary": "Found 3 vulnerabilities",
        "key_findings": ["SQL Injection in app.py"],
        "suggested_actions": ["Verify SQL injection"],
        "context_data": {"findings": [{"title": "SQLi"}]},
        "confidence": 0.7,
    })
    assert result["phase"] == "analysis"
    assert len(result["key_findings"]) == 1


def test_verification_result():
    tool = VerificationResult()
    assert tool.spec.name == "verification_result"
    result = tool.execute({
        "summary": "2 findings confirmed",
        "key_findings": ["SQLi confirmed"],
        "suggested_actions": ["Fix SQL injection"],
        "context_data": {"verified_findings": []},
        "confidence": 0.9,
    })
    assert result["phase"] == "verification"
    assert result["confidence"] == 0.9


def test_build_handoff_payload():
    payload = _build_handoff_payload({
        "summary": "Test",
        "key_findings": ["a", "b"],
        "insights": ["c"],
        "suggested_actions": ["d"],
        "attention_points": ["e"],
        "priority_areas": ["f"],
        "context_data": {"x": 1},
        "confidence": 0.75,
    })
    assert payload["summary"] == "Test"
    assert len(payload["key_findings"]) == 2
    assert payload["confidence"] == 0.75
