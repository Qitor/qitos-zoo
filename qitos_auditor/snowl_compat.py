"""Snowl compatibility declaration for qitos_auditor.

Snowl Adapter SDK calls create_snowl_agent() to obtain a QitOS AgentModule,
then wraps it for evaluation. This module only contains QitOS-side code.
"""


def create_snowl_agent(**kwargs):
    """Create a Snowl-compatible Agent from qitos_auditor."""
    from qitos_zoo.qitos_auditor.agents.orchestrator import OrchestratorAgent
    return OrchestratorAgent(**kwargs)


REQUIRED_TOOLS = ["file_read", "file_write", "shell", "search", "web_fetch"]
REQUIRED_ENV = {"type": "host", "capabilities": ["filesystem", "command", "network"]}
