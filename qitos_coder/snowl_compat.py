"""Snowl compatibility declaration for qitos_coder.

Snowl Adapter SDK calls create_snowl_agent() to obtain a QitOS AgentModule,
then wraps it for evaluation. This module only contains QitOS-side code.
"""


def create_snowl_agent(**kwargs):
    """Create a Snowl-compatible Agent from qitos_coder.

    Snowl Adapter SDK is responsible for calling this function and
    performing wrap() conversion on the Snowl side.
    """
    from qitos_zoo.qitos_coder.agent import ClaudeCodeAgent
    return ClaudeCodeAgent(**kwargs)


# Declaration of tools and environment requirements for evaluation
REQUIRED_TOOLS = ["shell", "file_read", "file_write", "file_edit", "search"]
REQUIRED_ENV = {"type": "host", "capabilities": ["filesystem", "command", "network"]}
