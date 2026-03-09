"""
Utility functions for the Mask SDK.

Provides shared recursive data structures traversal algorithms used by the
various framework integration hooks (LangChain, LlamaIndex, ADK) to find
and intercept tokens/PII hidden deep inside nested dictionaries, lists,
and Pydantic models.
"""

from typing import Any

from mask.core.vault import _decode_lenient
from mask.core.fpe import looks_like_token
from mask.core.scanner import get_scanner


def deep_decode(obj: Any) -> Any:
    """Walk *obj* recursively and detokenise every value that looks like a Mask token."""
    if isinstance(obj, str):
        if looks_like_token(obj):
            # Use lenient decode semantics: resolve known tokens to plaintext,
            # but leave unknown/expired tokens untouched.
            return _decode_lenient(obj)
        return obj
    if isinstance(obj, dict):
        return {k: deep_decode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(deep_decode(item) for item in obj)
        
    # Introspect pydantic models dynamically
    if hasattr(obj, "dict") or hasattr(obj, "model_dump"):
        for field_name in getattr(obj, "__fields__", getattr(obj, "model_fields", {})):
            val = getattr(obj, field_name, None)
            if val is not None:
                setattr(obj, field_name, deep_decode(val))

    return obj


def deep_encode_pii(obj: Any) -> Any:
    """Walk *obj* and tokenise PII using Microsoft Presidio."""
    if isinstance(obj, str):
        # Avoid double-encoding values that are already Mask tokens
        if looks_like_token(obj):
            return obj
        scanner = get_scanner()
        return scanner.scan_and_tokenize(obj)
    if isinstance(obj, dict):
        return {k: deep_encode_pii(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(deep_encode_pii(item) for item in obj)
        
    # Introspect pydantic models dynamically
    if hasattr(obj, "dict") or hasattr(obj, "model_dump"):
        for field_name in getattr(obj, "__fields__", getattr(obj, "model_fields", {})):
            val = getattr(obj, field_name, None)
            if val is not None:
                setattr(obj, field_name, deep_encode_pii(val))

    return obj
