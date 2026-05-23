"""End-to-end functional tests for DeepAudit security auditing.

Tests exercise the full AuditFlow pipeline with real LLMs,
validating that the auditor can actually discover vulnerabilities.

Tiers:
- Tier 1 (Smoke): Does the full pipeline run without crashing?
- Tier 2 (Reconnaissance): Does the agent identify tech stack and entry points?
- Tier 3 (Vulnerability Discovery): Does the agent find known vulnerabilities?

Run examples:
    # Single model, Tier 1 only (cheapest)
    AUDITOR_E2E_MODEL=deepseek-v4-pro pytest qitos_zoo/qitos_auditor/tests/test_e2e.py -k "Tier1" -v -s

    # All tiers, single model
    AUDITOR_E2E_MODEL=deepseek-v4-pro pytest qitos_zoo/qitos_auditor/tests/test_e2e.py -v -s

    # All models, Tier 1
    pytest qitos_zoo/qitos_auditor/tests/test_e2e.py -k "Tier1" -v -s

    # Specific combination
    AUDITOR_E2E_MODEL=glm-5.1 pytest qitos_zoo/qitos_auditor/tests/test_e2e.py -k "synthetic_flask and Tier3" -v -s
"""

from __future__ import annotations

import os

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

from qitos_zoo.qitos_auditor.e2e.models import MODEL_ENDPOINTS
from qitos_zoo.qitos_auditor.e2e.criteria import TIER_PASS_RATES
from qitos_zoo.qitos_auditor.e2e.targets import TARGETS, SYNTHETIC_FLASK


# ── Model selection ───────────────────────────────────────────────

def _get_model_endpoints():
    """Get model endpoints to test.

    If AUDITOR_E2E_MODEL is set, test only that model.
    Otherwise test all 6 models.
    """
    specified = os.getenv("AUDITOR_E2E_MODEL", "").strip()
    if specified:
        if specified not in MODEL_ENDPOINTS:
            pytest.skip(f"Unknown model endpoint: {specified}")
        return [specified]
    return list(MODEL_ENDPOINTS.keys())


# ── Synthetic Flask app fixture ───────────────────────────────────

SYNTHETIC_FLASK_CODE = '''\
from flask import Flask, request, render_template_string
import os
import sqlite3

app = Flask(__name__)
app.secret_key = "dev"  # Hardcoded secret

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    return "OK"

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    # XSS vulnerability
    return f"<h1>Hello {name}!</h1>"

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # Command injection vulnerability
    result = os.system(f"ping -c 1 {host}")
    return str(result)

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Path traversal vulnerability
    with open(f'/uploads/{filename}', 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)
'''


@pytest.fixture(scope="module")
def synthetic_flask_dir(tmp_path_factory):
    """Create the synthetic Flask target for testing."""
    tmp = tmp_path_factory.mktemp("synthetic_flask")
    (tmp / "app.py").write_text(SYNTHETIC_FLASK_CODE)
    (tmp / "requirements.txt").write_text("flask==2.3.0\n")
    return str(tmp)


# ── Parameterized model fixture ──────────────────────────────────

def _model_ids():
    return _get_model_endpoints()


@pytest.fixture(scope="module", params=_model_ids(), ids=lambda x: x)
def model_endpoint(request):
    return request.param


# ── Tier 1 — Smoke ──────────────────────────────────────────────

class TestTier1Smoke:
    """Tier 1: Does the full pipeline run without crashing?"""

    def test_pipeline_completes_synthetic_flask(self, model_endpoint, synthetic_flask_dir):
        from qitos_zoo.qitos_auditor.e2e.runner import run_auditor_e2e_task

        # Patch the synthetic target's local_path
        SYNTHETIC_FLASK.local_path = synthetic_flask_dir

        report = run_auditor_e2e_task(
            target_name="synthetic-flask",
            tier=1,
            model_endpoint=model_endpoint,
        )
        print(f"\n{report.summary()}")
        assert report.tier_passed(TIER_PASS_RATES[1]), (
            f"Tier 1 failed for {model_endpoint}:\n{report.summary()}"
        )


# ── Tier 2 — Reconnaissance ─────────────────────────────────────

class TestTier2Reconnaissance:
    """Tier 2: Does the agent identify tech stack and entry points?"""

    def test_recon_synthetic_flask(self, model_endpoint, synthetic_flask_dir):
        from qitos_zoo.qitos_auditor.e2e.runner import run_auditor_e2e_task

        SYNTHETIC_FLASK.local_path = synthetic_flask_dir

        report = run_auditor_e2e_task(
            target_name="synthetic-flask",
            tier=2,
            model_endpoint=model_endpoint,
        )
        print(f"\n{report.summary()}")
        assert report.required_passed, (
            f"Tier 2 required criteria failed for {model_endpoint}:\n{report.summary()}"
        )

    def test_recon_dvwa_src(self, model_endpoint):
        from qitos_zoo.qitos_auditor.e2e.runner import run_auditor_e2e_task

        report = run_auditor_e2e_task(
            target_name="dvwa-src",
            tier=2,
            model_endpoint=model_endpoint,
        )
        print(f"\n{report.summary()}")
        assert report.required_passed, (
            f"Tier 2 required criteria failed for {model_endpoint}:\n{report.summary()}"
        )


# ── Tier 3 — Vulnerability Discovery ─────────────────────────────

class TestTier3VulnDiscovery:
    """Tier 3: Does the agent find known vulnerabilities?"""

    def test_vuln_discovery_synthetic_flask(self, model_endpoint, synthetic_flask_dir):
        from qitos_zoo.qitos_auditor.e2e.runner import run_auditor_e2e_task

        SYNTHETIC_FLASK.local_path = synthetic_flask_dir

        report = run_auditor_e2e_task(
            target_name="synthetic-flask",
            tier=3,
            model_endpoint=model_endpoint,
        )
        print(f"\n{report.summary()}")
        assert report.required_passed, (
            f"Tier 3 required criteria failed for {model_endpoint}:\n{report.summary()}"
        )
        assert report.pass_rate >= TIER_PASS_RATES[3], (
            f"Tier 3 pass rate {report.pass_rate:.0%} < {TIER_PASS_RATES[3]:.0%} "
            f"for {model_endpoint}"
        )

    def test_vuln_discovery_dvwa_src(self, model_endpoint):
        from qitos_zoo.qitos_auditor.e2e.runner import run_auditor_e2e_task

        report = run_auditor_e2e_task(
            target_name="dvwa-src",
            tier=3,
            model_endpoint=model_endpoint,
        )
        print(f"\n{report.summary()}")
        assert report.required_passed, (
            f"Tier 3 required criteria failed for {model_endpoint}:\n{report.summary()}"
        )
