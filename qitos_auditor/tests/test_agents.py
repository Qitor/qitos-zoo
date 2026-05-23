"""Tests for agent state and initialization."""

from qitos_zoo.qitos_auditor.agents import (
    OrchestratorAgent, OrchestratorState, HandoffPayload, FindingEntry,
    ReconAgent, ReconState,
    AnalysisAgent, AnalysisState,
    VerificationAgent, VerificationState,
)


def test_orchestrator_state_init():
    state = OrchestratorState(task="Test audit")
    assert state.current_phase == "recon"
    assert state.findings == []
    assert state.handoffs == {}


def test_recon_state_init():
    state = ReconState(task="Scan project")
    assert state.target_path == ""
    assert state.tech_stack == {}
    assert state.files_read == []


def test_analysis_state_init():
    state = AnalysisState(task="Find vulnerabilities")
    assert state.findings == []
    assert state.scanner_results == {}


def test_verification_state_init():
    state = VerificationState(task="Verify findings")
    assert state.findings_to_verify == []
    assert state.verified_findings == []
    assert state.confirmed_count == 0


def test_handoff_payload():
    payload = HandoffPayload(
        summary="Recon complete",
        key_findings=["Flask app detected"],
        confidence=0.8,
    )
    assert payload.summary == "Recon complete"
    assert len(payload.key_findings) == 1
    assert payload.confidence == 0.8

    # Test to_prompt_context
    ctx = payload.to_prompt_context()
    assert "Recon complete" in ctx
    assert "Flask app detected" in ctx


def test_finding_entry():
    entry = FindingEntry(
        title="SQL Injection",
        severity="critical",
        file="app.py",
        line=10,
        cwe_id="CWE-89",
    )
    d = entry.to_dict()
    assert d["title"] == "SQL Injection"
    assert d["severity"] == "critical"
    assert d["cwe_id"] == "CWE-89"


def test_orchestrator_agent_init():
    agent = OrchestratorAgent(target_path="/tmp/test")
    state = agent.init_state("Audit this code")
    assert state.target_path == "/tmp/test"
    assert state.current_phase == "recon"


def test_recon_agent_init():
    agent = ReconAgent(target_path="/tmp/test")
    state = agent.init_state("Scan project")
    assert state.target_path == "/tmp/test"


def test_analysis_agent_init():
    agent = AnalysisAgent(target_path="/tmp/test")
    state = agent.init_state("Find vulnerabilities")
    assert state.target_path == "/tmp/test"


def test_verification_agent_init():
    agent = VerificationAgent(target_path="/tmp/test")
    state = agent.init_state("Verify findings")
    assert state.target_path == "/tmp/test"
