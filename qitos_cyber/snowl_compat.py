"""Snowl compatibility declaration for qitos_cyber.

Snowl Adapter SDK calls create_snowl_agent() to obtain a QitOS AgentModule,
then wraps it for evaluation. This module only contains QitOS-side code.
"""


def create_snowl_agent(**kwargs):
    """Create a Snowl-compatible Agent from qitos_cyber."""
    from qitos_zoo.qitos_cyber.pentagi.agents.primary import PrimaryPentestAgent
    return PrimaryPentestAgent(**kwargs)


REQUIRED_TOOLS = ["shell", "file_read", "file_write", "search", "nmap", "curl"]
REQUIRED_ENV = {"type": "docker", "capabilities": ["filesystem", "command", "network", "privileged"]}
