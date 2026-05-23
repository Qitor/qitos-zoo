"""Tests for orchestration — AuditFlow, PhaseManager, and AuditResult."""

from qitos_zoo.qitos_auditor.config.defaults import DeepAuditConfig
from qitos_zoo.qitos_auditor.orchestrator.flow import AuditFlow, AuditResult
from qitos_zoo.qitos_auditor.orchestrator.phase_manager import PhaseManager
from qitos_zoo.qitos_auditor.agents.orchestrator import HandoffPayload


def test_audit_result():
    result = AuditResult(task="Test audit")
    assert result.task == "Test audit"
    assert result.findings == []
    assert result.status == "completed"
    assert result.critical_count == 0


def test_audit_result_with_findings():
    result = AuditResult(
        task="Test",
        findings=[
            {"severity": "critical", "title": "SQLi"},
            {"severity": "high", "title": "XSS"},
            {"severity": "medium", "title": "CSRF"},
            {"severity": "low", "title": "Info leak"},
        ],
    )
    assert len(result.findings) == 4


def test_phase_manager():
    pm = PhaseManager()
    assert pm.current_phase == "recon"
    assert not pm.is_phase_completed("recon")

    # Complete recon
    handoff = HandoffPayload(summary="Recon done", confidence=0.8)
    pm.complete_phase("recon", handoff)
    assert pm.current_phase == "analysis"
    assert pm.is_phase_completed("recon")
    assert pm.get_handoff("recon") == handoff

    # Get previous handoff for analysis
    prev = pm.get_previous_handoff()
    assert prev == handoff

    # Complete analysis
    analysis_handoff = HandoffPayload(summary="Analysis done", confidence=0.7)
    pm.complete_phase("analysis", analysis_handoff)
    assert pm.current_phase == "verification"

    # Complete verification
    verify_handoff = HandoffPayload(summary="Verification done", confidence=0.9)
    pm.complete_phase("verification", verify_handoff)
    assert pm.current_phase == "reporting"
    assert pm.is_complete()


def test_deep_audit_config():
    config = DeepAuditConfig()
    assert config.target_path == "."
    flow = AuditFlow(config=config)
    assert flow.config == config


def test_runner_import():
    from qitos_zoo.qitos_auditor import DeepAuditRunner, DeepAuditConfig
    config = DeepAuditConfig()
    runner = DeepAuditRunner(config)
    assert runner.config == config
