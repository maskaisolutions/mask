"""
Info Agent Module.

This package exposes the demo `secure_data_assistant` agent as `root_agent`
for convenience. The agent depends on the optional Google ADK package; to
avoid import-time failures when that dependency is not installed (for example
in unit tests), we degrade gracefully and expose `root_agent = None`.
"""

try:
    from .vault_agent import secure_data_assistant as root_agent
except Exception:
    root_agent = None
