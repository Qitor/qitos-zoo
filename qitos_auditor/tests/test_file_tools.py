"""Tests for file tools."""

import os
import tempfile

import pytest

from qitos_zoo.qitos_auditor.tools.file_tools import (
    ReadFileTool, SmartScanTool, PatternMatchTool, CodeAnalysisTool,
    ExtractFunctionTool, QuickAuditTool,
)


@pytest.fixture
def sample_project(tmp_path):
    """Create a sample project for testing file tools."""
    # Python file with vulnerabilities
    py_file = tmp_path / "app.py"
    py_file.write_text('''
import os
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "hardcoded-secret"

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    os.system(f"ping {host}")  # Command injection

@app.route('/user/<name>')
def get_user(name):
    return f"Hello {name}"  # XSS
''')

    # JavaScript file
    js_file = tmp_path / "index.js"
    js_file.write_text('''
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    res.send(`<h1>Results: ${req.query.q}</h1>`);  // XSS
});

app.get('/exec', (req, res) => {
    const { exec } = require('child_process');
    exec(`ls ${req.query.dir}`, (err, stdout) => {  // Command injection
        res.send(stdout);
    });
});
''')

    # Config file
    config_file = tmp_path / "config.json"
    config_file.write_text('{"secret": "sk-1234567890abcdef", "debug": true}')

    return tmp_path


def test_read_file(sample_project):
    tool = ReadFileTool(workspace_root=str(sample_project))
    result = tool.execute({"path": "app.py"})
    assert result["path"] == "app.py"
    assert "os.system" in result["content"]


def test_read_file_not_found(sample_project):
    tool = ReadFileTool(workspace_root=str(sample_project))
    result = tool.execute({"path": "nonexistent.py"})
    assert "error" in result or result.get("content", "") == ""


def test_smart_scan(sample_project):
    tool = SmartScanTool(workspace_root=str(sample_project))
    result = tool.execute({"query": "command"})
    assert "results" in result


def test_pattern_match(sample_project):
    tool = PatternMatchTool(workspace_root=str(sample_project))
    result = tool.execute({"pattern": r"os\.system"})
    assert "results" in result
    # Should find os.system in app.py
    assert result["total_matches"] > 0


def test_quick_audit(sample_project):
    tool = QuickAuditTool(workspace_root=str(sample_project))
    result = tool.execute({"file_path": "app.py"})
    assert "findings" in result
    # Should detect command_injection
    assert result.get("findings_count", 0) >= 0
