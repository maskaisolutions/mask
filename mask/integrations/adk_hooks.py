"""
Google ADK tool interception hooks.

Replaces the hardcoded field-name checks from the original hooks.py
with recursive, dynamic token scanning powered by the FPE heuristic
detector.  Works with *any* tool schema — no config required.
"""

import logging
from typing import Any, Dict, Optional

from mask.core.utils import deep_decode, deep_encode_pii

logger = logging.getLogger("mask.integrations.adk")

# Re-export for backwards compatibility with existing code
__all__ = ["decrypt_before_tool", "encrypt_after_tool"]


# ---------------------------------------------------------------------------
# ADK callbacks (signature matches google.adk hook protocol)
# ---------------------------------------------------------------------------

def decrypt_before_tool(
    tool: Any,
    args: Dict[str, Any],
    tool_context: Any,
) -> Optional[Dict[str, Any]]:
    """Pre-tool hook: detokenise every Mask token found in *args*.

    This replaces the old ``decrypt_tool_inputs`` which only checked
    hard-coded ``email`` / ``email_address`` keys.
    """
    agent_name = getattr(tool_context, "agent_name", "unknown")
    tool_name = getattr(tool, "name", str(tool))
    logger.info("[pre-hook] decrypting for %s → %s", agent_name, tool_name)

    decoded_args = deep_decode(args)
    # Mutate in place (ADK expects args dict to be modified)
    args.update(decoded_args)
    return None


def encrypt_after_tool(
    tool: Any,
    args: Dict[str, Any],
    tool_context: Any,
    tool_response: Any,
) -> Any:
    """Post-tool hook: tokenise any raw PII found in *args* or *tool_response*.

    This replaces the old ``encrypt_tool_outputs`` which only checked
    for the ``email`` key.
    """
    agent_name = getattr(tool_context, "agent_name", "unknown")
    tool_name = getattr(tool, "name", str(tool))
    logger.info("[post-hook] encrypting for %s → %s", agent_name, tool_name)

    # Encrypt any plaintext emails that leaked into the args
    encoded_args = deep_encode_pii(args)
    args.update(encoded_args)

    # Encrypt tool_response if it is a string, dict, or list
    if isinstance(tool_response, (str, dict, list)):
        encoded_resp = deep_encode_pii(tool_response)
        if isinstance(tool_response, dict) and isinstance(encoded_resp, dict):
            tool_response.update(encoded_resp)
        return encoded_resp

    return None
