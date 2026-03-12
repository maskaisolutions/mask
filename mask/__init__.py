"""
Mask Privacy SDK
Just-In-Time Privacy Middleware for AI Agents.

Provides format-preserving encryption, local/distributed vaulting,
and framework-agnostic tool interception hooks.
"""

__version__ = "0.3.3"

from mask.core.vault import (
    get_vault,
    encode,
    decode,
    aencode,
    adecode,
    detokenize_text,
    adetokenize_text,
)
from mask.core.fpe import generate_fpe_token, looks_like_token, reset_master_key

# --- Public API: Expose entity detection with confidence scores ---
from mask.core.scanner import get_scanner, RemotePresidioScanner


def detect_entities_with_confidence(
    text,
    pipeline=None,
    confidence_threshold=0.7,
    context=None,
    aggressive=False,
):
    """Detect PII entities in text and return a list of dicts with type, value, method, confidence, and masked_value."""
    scanner = get_scanner()
    return scanner.scan_and_return_entities(
        text,
        pipeline=pipeline,
        confidence_threshold=confidence_threshold,
        context=context,
        aggressive=aggressive,
    )


async def ascan_and_tokenize(
    text,
    pipeline=None,
    confidence_threshold=0.7,
    context=None,
    aggressive=False,
):
    """Async variant of get_scanner().scan_and_tokenize()."""
    scanner = get_scanner()
    return await scanner.ascan_and_tokenize(
        text,
        pipeline=pipeline,
        confidence_threshold=confidence_threshold,
        context=context,
        aggressive=aggressive,
    )


# --- Public API: Client convenience class ---
from mask.client import MaskClient


# --- Integration decorators (lazy imports to avoid hard dependency) ---
def secure_tool(*args, **kwargs):
    """Drop-in decorator for LangChain tools with automatic PII protection.

    Usage::

        from mask import secure_tool

        @secure_tool
        def send_email(email: str, body: str) -> str: ...
    """
    from mask.integrations.langchain_hooks import secure_tool as _secure_tool
    return _secure_tool(*args, **kwargs)


__all__ = [
    "get_vault",
    "encode",
    "decode",
    "aencode",
    "adecode",
    "detokenize_text",
    "adetokenize_text",
    "generate_fpe_token",
    "looks_like_token",
    "reset_master_key",
    "detect_entities_with_confidence",
    "ascan_and_tokenize",
    "MaskClient",
    "secure_tool",
]
