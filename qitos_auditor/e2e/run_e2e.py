#!/usr/bin/env python3
"""Run DeepAudit e2e tests across multiple model endpoints.

Usage:
    # Run Tier 1 smoke test on a single model
    python -m qitos_zoo.qitos_auditor.e2e.run_e2e --model deepseek-v4-flash --tier 1

    # Run Tier 1+2 on all models
    python -m qitos_zoo.qitos_auditor.e2e.run_e2e --tier 2

    # Run full Tier 3 on all models (slow!)
    python -m qitos_zoo.qitos_auditor.e2e.run_e2e --tier 3

    # Run on a specific target
    python -m qitos_zoo.qitos_auditor.e2e.run_e2e --model glm-5.1 --target synthetic-flask
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict
from typing import Any, Dict, List

# Ensure project root is on path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from qitos_zoo.qitos_auditor.e2e.criteria import get_criteria, TIER_PASS_RATES
from qitos_zoo.qitos_auditor.e2e.models import MODEL_ENDPOINTS, build_llm_for_endpoint
from qitos_zoo.qitos_auditor.e2e.report import CriterionScore, ScoreReport
from qitos_zoo.qitos_auditor.e2e.scorer import AuditorE2EScorer
from qitos_zoo.qitos_auditor.e2e.target_manager import AuditTargetManager
from qitos_zoo.qitos_auditor.e2e.targets import TARGETS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("e2e_runner")


def run_single_test(
    model_name: str,
    target_name: str,
    tier: int,
    playground_root: str = "playground",
) -> Dict[str, Any]:
    """Run a single e2e test and return results dict."""
    from qitos_zoo.qitos_auditor.config.defaults import DeepAuditConfig
    from qitos_zoo.qitos_auditor.orchestrator.flow import AuditFlow

    target = TARGETS.get(target_name)
    if target is None:
        return {"error": f"Unknown target: {target_name}"}

    endpoint = MODEL_ENDPOINTS.get(model_name)
    if endpoint is None:
        return {"error": f"Unknown model: {model_name}"}

    criteria = get_criteria(tier, target_name)
    pass_rate = TIER_PASS_RATES.get(tier, 1.0)

    try:
        # Prepare target
        manager = AuditTargetManager(target, playground_root=playground_root)
        target_path = manager.prepare()
        ground_truth = manager.get_ground_truth()

        # Build LLM
        llm = build_llm_for_endpoint(model_name)

        # Tier-based step budgets
        tier_budgets = {
            1: {"max_steps_recon": 6, "max_steps_analysis": 6, "max_steps_verification": 5},
            2: {"max_steps_recon": 8, "max_steps_analysis": 10, "max_steps_verification": 8},
            3: {"max_steps_recon": 12, "max_steps_analysis": 20, "max_steps_verification": 15},
        }
        budget = tier_budgets.get(tier, tier_budgets[2])

        # Task description
        if tier == 1:
            task = "Perform a quick security audit of this codebase"
        elif tier == 2:
            task = (
                "Analyze the codebase structure and identify the technology stack, "
                "entry points, and security-relevant code patterns."
            )
        else:
            task = (
                "Perform a comprehensive security audit. Identify all security "
                "vulnerabilities including injection flaws, auth issues, and crypto weaknesses. "
                "For each finding provide the specific file, line number, and evidence."
            )

        config = DeepAuditConfig(
            target_path=target_path,
            fast_mode=(tier <= 2),
            enable_semgrep=(tier >= 3),
            enable_bandit=(tier >= 3 and "python" in target.languages),
            enable_gitleaks=(tier >= 3),
            enable_npm_audit=False,
            enable_osv_scanner=False,
            sandbox_enabled=False,
            knowledge_enabled=True,
            report_format="markdown",
            **budget,
        )

        # Run
        started = time.time()
        flow = AuditFlow(config=config, llm=llm)
        result = flow.run(task, target_path=target_path)
        elapsed = time.time() - started

        # Score
        scorer = AuditorE2EScorer()
        report = scorer.score(
            result, criteria, ground_truth,
            tier=tier, target_name=target_name,
        )

        # Build result summary
        total_passed = sum(1 for s in report.scores if s.passed)
        total_criteria = len(report.scores)
        overall_pass = (total_passed / total_criteria >= pass_rate) if total_criteria > 0 else False

        return {
            "model": model_name,
            "target": target_name,
            "tier": tier,
            "status": result.status,
            "duration_s": round(elapsed, 1),
            "findings_count": len(result.findings),
            "findings": [
                {
                    "severity": f.get("severity", "?"),
                    "title": f.get("title", "?"),
                    "file_path": f.get("file_path", "?"),
                    "verdict": f.get("verdict", "uncertain"),
                }
                for f in result.findings[:20]
            ],
            "handoff_phases": list(result.handoffs.keys()),
            "criteria_passed": total_passed,
            "criteria_total": total_criteria,
            "pass_rate_threshold": pass_rate,
            "overall_pass": overall_pass,
            "score_details": [
                {"name": s.name, "passed": s.passed, "points": s.points, "detail": s.detail}
                for s in report.scores
            ],
        }

    except Exception as e:
        import traceback
        return {
            "model": model_name,
            "target": target_name,
            "tier": tier,
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


def print_results_table(results: List[Dict[str, Any]]) -> None:
    """Print a summary table of all test results."""
    print("\n" + "=" * 90)
    print("DEEPAUDIT E2E TEST RESULTS")
    print("=" * 90)

    # Header
    print(f"{'Model':<22} {'Target':<18} {'Tier':<5} {'Status':<10} "
          f"{'Duration':<9} {'Findings':<9} {'Criteria':<10} {'Pass':<5}")
    print("-" * 90)

    for r in results:
        if "error" in r:
            print(f"{r.get('model','?'):<22} {r.get('target','?'):<18} T{r.get('tier','?'):<4} "
                  f"{'ERROR':<10} {'-':<9} {'-':<9} {'-':<10} {'-':<5}")
            continue

        status_icon = "OK" if r["status"] == "completed" else r["status"][:8]
        pass_icon = "PASS" if r["overall_pass"] else "FAIL"
        criteria_str = f"{r['criteria_passed']}/{r['criteria_total']}"

        print(f"{r['model']:<22} {r['target']:<18} T{r['tier']:<4} {status_icon:<10} "
              f"{r['duration_s']:>7.1f}s {r['findings_count']:<9} {criteria_str:<10} {pass_icon:<5}")

    print("-" * 90)

    # Summary
    passed = sum(1 for r in results if r.get("overall_pass"))
    failed = sum(1 for r in results if not r.get("overall_pass") and "error" not in r)
    errors = sum(1 for r in results if "error" in r)
    total = len(results)
    print(f"Total: {total} | Passed: {passed} | Failed: {failed} | Errors: {errors}")

    # Findings summary
    all_findings = []
    for r in results:
        if "findings" in r:
            all_findings.extend(r["findings"])

    if all_findings:
        print(f"\nTotal findings across all runs: {len(all_findings)}")
        by_severity = {}
        for f in all_findings:
            sev = f.get("severity", "unknown").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        sev_str = " | ".join(f"{k}: {v}" for k, v in sorted(by_severity.items()))
        print(f"By severity: {sev_str}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Run DeepAudit e2e tests")
    parser.add_argument(
        "--model", "-m",
        help="Model endpoint name (default: all models)",
    )
    parser.add_argument(
        "--target", "-t",
        default="synthetic-flask",
        help="Target name (default: synthetic-flask)",
    )
    parser.add_argument(
        "--tier", type=int, default=2,
        help="Test tier 1-3 (default: 2)",
    )
    parser.add_argument(
        "--all-models", action="store_true",
        help="Run on all available models",
    )
    parser.add_argument(
        "--all-targets", action="store_true",
        help="Run on all available targets",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--playground-root", default="playground",
        help="Root directory for cloned repos",
    )
    args = parser.parse_args()

    # Determine models
    if args.model:
        model_names = [args.model]
    else:
        model_names = list(MODEL_ENDPOINTS.keys())

    # Determine targets
    if args.all_targets:
        target_names = list(TARGETS.keys())
    else:
        target_names = [args.target]

    # Determine tiers
    tiers = [args.tier]

    logger.info(f"Running e2e: models={model_names}, targets={target_names}, tiers={tiers}")

    results: List[Dict[str, Any]] = []
    total_runs = len(model_names) * len(target_names) * len(tiers)
    run_idx = 0

    for model_name in model_names:
        for target_name in target_names:
            target = TARGETS.get(target_name)
            if target is None:
                continue
            for tier in tiers:
                if tier < target.min_tier or tier > target.max_tier:
                    continue
                run_idx += 1
                logger.info(
                    f"[{run_idx}/{total_runs}] {model_name} x {target_name} x T{tier}"
                )
                result = run_single_test(
                    model_name, target_name, tier,
                    playground_root=args.playground_root,
                )
                results.append(result)

                # Log intermediate result
                if "error" in result:
                    logger.error(f"  ERROR: {result['error'][:200]}")
                else:
                    logger.info(
                        f"  status={result['status']}, findings={result['findings_count']}, "
                        f"criteria={result['criteria_passed']}/{result['criteria_total']}, "
                        f"pass={result['overall_pass']}, duration={result['duration_s']}s"
                    )

    # Print results table
    print_results_table(results)

    # Save JSON output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {args.output}")

    # Exit code: 0 if all passed, 1 otherwise
    all_passed = all(r.get("overall_pass", False) for r in results)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
