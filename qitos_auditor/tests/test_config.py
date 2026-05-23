"""Tests for DeepAuditConfig."""

from qitos_zoo.qitos_auditor.config.defaults import DeepAuditConfig


def test_default_config():
    config = DeepAuditConfig()
    assert config.model_provider == "openai-compatible"
    assert config.model_name == "qwen-plus"
    assert config.max_steps_recon == 15
    assert config.max_steps_analysis == 30
    assert config.max_steps_verification == 25
    assert config.max_steps_orchestrator == 20
    assert config.max_total_steps == 150
    assert config.enable_semgrep is True
    assert config.enable_bandit is True
    assert config.report_format == "markdown"


def test_fast_mode():
    config = DeepAuditConfig(fast_mode=True)
    assert config.max_steps_recon == 8
    assert config.max_steps_analysis == 15
    assert config.max_steps_verification == 12


def test_custom_config():
    config = DeepAuditConfig(
        target_path="/tmp/test",
        language="zh",
        max_steps_analysis=50,
        enable_trufflehog=True,
        enable_kunlun=True,
    )
    assert config.target_path == "/tmp/test"
    assert config.language == "zh"
    assert config.max_steps_analysis == 50
    assert config.enable_trufflehog is True
    assert config.enable_kunlun is True
