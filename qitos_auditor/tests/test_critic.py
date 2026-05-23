"""Tests for critic modules."""

from qitos_zoo.qitos_auditor.critic import (
    FilePathValidationCritic,
    RepeatedToolCallCritic,
    EmptyResponseCritic,
    AuditProgressCritic,
    GracefulShutdownCritic,
)
from qitos.core.decision import Decision


def _make_decision(mode="act", rationale="", actions=None):
    """Helper to create Decision objects with the correct API."""
    return Decision(mode=mode, actions=actions or [], rationale=rationale)


def _make_action(tool_name, args=None):
    """Helper to create action-like objects."""
    return type("Action", (), {"tool_name": tool_name, "name": tool_name, "args": args or {}})()


def test_repeated_tool_call_critic():
    critic = RepeatedToolCallCritic(max_repeats=2)

    action = _make_action("read_file", {"file_path": "test.py"})
    decision = _make_decision(actions=[action])

    # First call should pass
    result = critic.evaluate(state=None, observation=None, decision=decision)
    assert result.action == "continue"

    # Second call should pass
    result = critic.evaluate(state=None, observation=None, decision=decision)
    assert result.action == "continue"

    # Third call (same args, 3rd time) should trigger retry
    result = critic.evaluate(state=None, observation=None, decision=decision)
    assert result.action == "retry"
    assert "Repeated tool call" in result.reason


def test_empty_response_critic():
    critic = EmptyResponseCritic(max_retries=2)

    # Empty decision should trigger retry
    decision = _make_decision(rationale="", actions=[])
    result = critic.evaluate(state=None, observation=None, decision=decision)
    assert result.action == "retry"
    assert "Empty" in result.reason

    # Non-empty decision should pass
    decision = _make_decision(rationale="I will read the file", actions=[])
    result = critic.evaluate(state=None, observation=None, decision=decision)
    assert result.action == "continue"


def test_graceful_shutdown_critic():
    critic = GracefulShutdownCritic(barrier_tool_name="done", steps_remaining_threshold=2)

    # State with plenty of steps remaining
    state = type("State", (), {"steps_taken": 5, "max_steps": 20})()
    action = _make_action("read_file")
    decision = _make_decision(actions=[action])
    result = critic.evaluate(state=state, observation=None, decision=decision)
    assert result.action == "continue"

    # State with few steps remaining
    state = type("State", (), {"steps_taken": 19, "max_steps": 20})()
    result = critic.evaluate(state=state, observation=None, decision=decision)
    assert result.action == "retry"
    assert "done" in result.reason

    # State with done action already should pass
    done_action = _make_action("done")
    decision = _make_decision(actions=[done_action])
    result = critic.evaluate(state=state, observation=None, decision=decision)
    assert result.action == "continue"


def test_audit_progress_critic():
    critic = AuditProgressCritic(stagnation_threshold=3)

    # State with no findings (stagnating)
    state = type("State", (), {"findings": []})()
    decision = _make_decision()
    result = critic.evaluate(state=state, observation=None, decision=decision)
    assert result.action == "continue"

    # Simulate stagnation — call 2: steps_without_progress=2, no trigger yet
    result = critic.evaluate(state=state, observation=None, decision=decision)
    assert result.action == "continue"
    assert result.instruction_patch is None

    # Call 3: steps_without_progress=3, triggers stagnation advisory
    result = critic.evaluate(state=state, observation=None, decision=decision)
    assert result.action == "continue"
    assert "PROGRESS NOTE" in (result.instruction_patch or "")
