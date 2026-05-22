"""E2E test runner — runs coding agent tests in the sandbox and reports results.

Usage:
    cd /Users/morinop/qitos
    python sandbox/run_e2e.py [test_name]

If no test_name given, runs all tests sequentially.
"""

from __future__ import annotations

import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

# Add project root to path
sys.path.insert(0, "/Users/morinop/qitos")

# LLM config (from existing live_test files)
API_KEY = "MajUa5noC1OtfZ3RxznY23AZYWYisTPGc4MKZJyXB9Q="
BASE_URL = "https://o8kjqm58o8ogcm5ek8aggddkb5ggk8dp.openapi-sj.sii.edu.cn/v1"
MODEL_NAME = "ds-v4-pro"

SANDBOX_DIR = "/Users/morinop/qitos/sandbox"


@dataclass
class TestResult:
    name: str
    passed: bool
    duration: float = 0.0
    error: Optional[str] = None
    steps: int = 0
    final_result_preview: str = ""
    stop_reason: str = ""


def make_llm(model: str = MODEL_NAME):
    from qitos.models import ModelFactory
    return ModelFactory.create(
        "openai-compatible",
        model=model,
        api_key=API_KEY,
        base_url=BASE_URL,
        temperature=0.1,
        max_tokens=4096,
    )


def make_agent(workspace_root: str = SANDBOX_DIR, permission_mode: str = "bypassPermissions", **kw):
    from qitos_zoo.qitos_coder.agent import ClaudeCodeAgent
    llm = make_llm()
    return ClaudeCodeAgent(
        llm=llm,
        workspace_root=workspace_root,
        permission_mode=permission_mode,
        max_steps=kw.pop("max_steps", 15),
        **kw,
    )


def run_agent(agent, task: str, max_steps: int = 15):
    from qitos.engine.states import RuntimeBudget
    engine = agent.build_engine(budget=RuntimeBudget(max_steps=max_steps))
    return engine.run(task)


# ── Test cases ─────────────────────────────────────────────────────────────

def test_read_and_summarize_file() -> TestResult:
    """Agent reads README.md and summarizes."""
    agent = make_agent()
    result = run_agent(agent, "Read the file README.md and tell me what QitOS is in 1-2 sentences.")
    final = result.state.final_result or ""
    ok = (
        result.step_count >= 1
        and len(final) > 20
        and ("qitos" in final.lower() or "agent" in final.lower())
    )
    return TestResult(
        name="read_and_summarize_file",
        passed=ok,
        steps=result.step_count,
        final_result_preview=final[:200],
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"step_count={result.step_count}, final={final[:200]}",
    )


def test_search_for_code_pattern() -> TestResult:
    """Agent uses Grep to find Engine class definition."""
    agent = make_agent()
    result = run_agent(agent, "Search the codebase for the class definition of 'Engine' using Grep. Tell me which file defines it.")
    final = result.state.final_result or ""
    ok = result.step_count >= 1 and "engine" in final.lower()
    return TestResult(
        name="search_for_code_pattern",
        passed=ok,
        steps=result.step_count,
        final_result_preview=final[:200],
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"final={final[:200]}",
    )


def test_glob_for_files() -> TestResult:
    """Agent uses Glob to find Python files."""
    agent = make_agent()
    result = run_agent(agent, "Use Glob to find all Python files under qitos/engine/ and list the first 5 filenames.")
    final = result.state.final_result or ""
    ok = result.step_count >= 1 and ".py" in final.lower()
    return TestResult(
        name="glob_for_files",
        passed=ok,
        steps=result.step_count,
        final_result_preview=final[:200],
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"final={final[:200]}",
    )


def test_create_file() -> TestResult:
    """Agent creates a new file with content."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=SANDBOX_DIR) as tmpdir:
        agent = make_agent(workspace_root=tmpdir)
        result = run_agent(agent, "Create a file called hello.py with a Python function called greet that takes a name and returns 'Hello, {name}!'.")
        hello_path = os.path.join(tmpdir, "hello.py")
        if os.path.isfile(hello_path):
            content = open(hello_path).read()
            ok = "def greet" in content and ("Hello" in content or "hello" in content.lower())
            err_detail = content[:200]
        else:
            ok = False
            err_detail = "File not created"
    return TestResult(
        name="create_file",
        passed=ok,
        steps=result.step_count,
        stop_reason=result.state.stop_reason or "",
        error=None if ok else err_detail,
    )


def test_edit_existing_file() -> TestResult:
    """Agent reads then edits a file."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=SANDBOX_DIR) as tmpdir:
        file_path = os.path.join(tmpdir, "calc.py")
        with open(file_path, "w") as f:
            f.write("def add(a, b):\n    return a + b\n\ndef multiply(a, b):\n    return a * b\n")

        agent = make_agent(workspace_root=tmpdir)
        result = run_agent(agent, "Read calc.py and add a 'subtract' function after the add function that returns a - b.")

        content = open(file_path).read()
        ok = "subtract" in content.lower() and "multiply" in content
    return TestResult(
        name="edit_existing_file",
        passed=ok,
        steps=result.step_count,
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"content={content[:300]}",
    )


def test_run_bash() -> TestResult:
    """Agent runs a bash command."""
    agent = make_agent()
    result = run_agent(agent, "Run 'git log --oneline -3' using Bash and tell me the most recent commit message.")
    final = result.state.final_result or ""
    ok = result.step_count >= 1 and len(final) > 10
    return TestResult(
        name="run_bash",
        passed=ok,
        steps=result.step_count,
        final_result_preview=final[:200],
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"final={final[:200]}",
    )


def test_plan_mode_read_only() -> TestResult:
    """Agent in plan mode should not modify files."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=SANDBOX_DIR) as tmpdir:
        file_path = os.path.join(tmpdir, "readonly.py")
        with open(file_path, "w") as f:
            f.write("ORIGINAL_CONTENT = True\n")

        agent = make_agent(workspace_root=tmpdir, permission_mode="plan")
        result = run_agent(agent, "Read the file readonly.py and describe it.", max_steps=8)

        content = open(file_path).read()
        ok = "ORIGINAL_CONTENT = True" in content
    return TestResult(
        name="plan_mode_read_only",
        passed=ok,
        steps=result.step_count,
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"File was modified! content={content[:200]}",
    )


def test_handles_nonexistent_file() -> TestResult:
    """Agent should handle missing file gracefully."""
    agent = make_agent()
    result = run_agent(agent, "Read the file /nonexistent/path/xyz123.py and tell me what's in it.", max_steps=5)
    final = result.state.final_result or ""
    ok = result.step_count >= 1 and any(
        kw in final.lower()
        for kw in ("not found", "does not exist", "no such file", "error", "cannot", "couldn")
    )
    return TestResult(
        name="handles_nonexistent_file",
        passed=ok,
        steps=result.step_count,
        final_result_preview=final[:200],
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"final={final[:200]}",
    )


def test_auto_permission_mode() -> TestResult:
    """Agent in auto mode should auto-approve safe reads."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=SANDBOX_DIR) as tmpdir:
        file_path = os.path.join(tmpdir, "auto_test.py")
        with open(file_path, "w") as f:
            f.write("x = 42\n")

        agent = make_agent(workspace_root=tmpdir, permission_mode="auto")
        # Verify auto_classifier is wired
        assert agent.permission_pipeline._auto_classifier is not None, "AutoClassifier not wired!"

        result = run_agent(agent, "Read auto_test.py and tell me the value of x.", max_steps=5)
        final = result.state.final_result or ""
        ok = "42" in final
    return TestResult(
        name="auto_permission_mode",
        passed=ok,
        steps=result.step_count,
        final_result_preview=final[:200],
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"final={final[:200]}",
    )


def test_streaming() -> TestResult:
    """Verify streaming produces output."""
    streamed: list[str] = []

    class Handler:
        def on_start(self): pass
        def on_delta(self, text): streamed.append(text)
        def on_end(self): pass

    agent = make_agent()
    from qitos.engine.states import RuntimeBudget
    engine = agent.build_engine(budget=RuntimeBudget(max_steps=5))
    engine.stream_callback = Handler()
    result = engine.run("What is 2+2? Answer in one word.")
    ok = len(streamed) > 0
    return TestResult(
        name="streaming",
        passed=ok,
        steps=result.step_count,
        stop_reason=result.state.stop_reason or "",
        error=None if ok else "No streaming chunks received",
    )


def test_step_by_step_api() -> TestResult:
    """Verify engine.step() + rebuild_observation works."""
    agent = make_agent()
    from qitos.engine.states import RuntimeBudget
    engine = agent.build_engine(budget=RuntimeBudget(max_steps=10))
    state, observation = engine.init_session("Read the file README.md and tell me what QitOS is.")

    steps = 0
    recovered = 0
    while steps < 5:
        step_result = engine.step(state, observation)
        steps += 1
        if step_result.recovered:
            recovered += 1
            state.advance_step()
            observation = engine.rebuild_observation(state)
            continue
        if step_result.stop:
            break
        if step_result.decision and step_result.decision.mode == "final":
            break
        state.advance_step()
        observation = step_result.observation

    ok = steps >= 1
    return TestResult(
        name="step_by_step_api",
        passed=ok,
        steps=steps,
        stop_reason=state.stop_reason or "",
        error=None if ok else f"steps={steps}",
    )


def test_multi_step_bugfix() -> TestResult:
    """Agent reads buggy code, finds bug, and fixes it."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=SANDBOX_DIR) as tmpdir:
        file_path = os.path.join(tmpdir, "buggy.py")
        with open(file_path, "w") as f:
            f.write(
                "def fibonacci(n):\n"
                "    if n <= 0:\n"
                "        return 0\n"
                "    if n == 1:\n"
                "        return 1\n"
                "    return fibonacci(n - 1) + fibonacci(n - 2)\n"
                "\n"
                "def factorial(n):\n"
                "    if n == 0:\n"
                "        return 1\n"
                "    return n * factorial(n)  # BUG: should be n-1\n"
            )
        agent = make_agent(workspace_root=tmpdir)
        result = run_agent(agent, "Read buggy.py. There is a bug in the factorial function on the last line. Fix it.", max_steps=10)
        content = open(file_path).read()
        ok = "n - 1" in content and "fibonacci" in content
    return TestResult(
        name="multi_step_bugfix",
        passed=ok,
        steps=result.step_count,
        stop_reason=result.state.stop_reason or "",
        error=None if ok else f"content={content[:400]}",
    )


# ── Runner ─────────────────────────────────────────────────────────────────

ALL_TESTS = [
    test_read_and_summarize_file,
    test_search_for_code_pattern,
    test_glob_for_files,
    test_create_file,
    test_edit_existing_file,
    test_run_bash,
    test_plan_mode_read_only,
    test_handles_nonexistent_file,
    test_auto_permission_mode,
    test_streaming,
    test_step_by_step_api,
    test_multi_step_bugfix,
]


def run_all(test_names: Optional[List[str]] = None):
    results: List[TestResult] = []
    tests_to_run = ALL_TESTS
    if test_names:
        tests_to_run = [t for t in ALL_TESTS if t.__name__ in test_names]

    print(f"\n{'='*70}")
    print(f"  QitOS Coding Agent E2E Tests")
    print(f"  Model: {MODEL_NAME}")
    print(f"  Sandbox: {SANDBOX_DIR}")
    print(f"  Tests: {len(tests_to_run)}")
    print(f"{'='*70}\n")

    for test_fn in tests_to_run:
        name = test_fn.__name__
        print(f"  ⏳ {name}...", end=" ", flush=True)
        start = time.time()
        try:
            r = test_fn()
            r.duration = time.time() - start
        except Exception as exc:
            r = TestResult(
                name=name,
                passed=False,
                duration=time.time() - start,
                error=f"EXCEPTION: {exc}\n{traceback.format_exc()}",
            )
        results.append(r)

        status = "✅ PASS" if r.passed else "❌ FAIL"
        print(f"{status} ({r.duration:.1f}s, {r.steps} steps)")
        if r.error:
            print(f"      Error: {r.error[:200]}")
        if r.final_result_preview:
            print(f"      Result: {r.final_result_preview[:150]}")

    # Summary
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    total_time = sum(r.duration for r in results)

    print(f"\n{'='*70}")
    print(f"  Results: {passed}/{len(results)} passed, {failed} failed")
    print(f"  Total time: {total_time:.1f}s")
    if failed:
        print(f"\n  Failed tests:")
        for r in results:
            if not r.passed:
                print(f"    - {r.name}: {r.error[:150] if r.error else 'unknown'}")
    print(f"{'='*70}\n")

    return results


if __name__ == "__main__":
    names = sys.argv[1:] if len(sys.argv) > 1 else None
    results = run_all(names)
    sys.exit(0 if all(r.passed for r in results) else 1)
