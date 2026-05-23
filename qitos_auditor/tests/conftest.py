"""Test fixtures and shared utilities for DeepAudit tests."""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

import pytest


@pytest.fixture
def sample_flask_app(tmp_path):
    """Create a sample Flask app with intentional vulnerabilities for testing."""
    app_code = '''
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
    app_file = tmp_path / "app.py"
    app_file.write_text(app_code)

    requirements = "flask==2.3.0\nsqlite3\n"
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(requirements)

    return tmp_path


@pytest.fixture
def audit_config(sample_flask_app):
    """Create a DeepAuditConfig for testing."""
    from qitos_zoo.qitos_auditor.config.defaults import DeepAuditConfig
    return DeepAuditConfig(
        target_path=str(sample_flask_app),
        fast_mode=True,
        enable_semgrep=False,
        enable_bandit=False,
        enable_gitleaks=False,
    )
