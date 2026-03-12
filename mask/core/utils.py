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
    def _deep_walk(obj: Any, op: str) -> Any:
        """Recursively walk obj and apply op ('decode' or 'encode') to Mask tokens/PII."""
        if isinstance(obj, str):
            if op == 'decode':
                return _decode_lenient(obj) if looks_like_token(obj) else obj
            if op == 'encode':
                if looks_like_token(obj):
                    return obj
                return get_scanner().scan_and_tokenize(obj)
        elif isinstance(obj, dict):
            return {k: _deep_walk(v, op) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return type(obj)(_deep_walk(item, op) for item in obj)
        else:
            # Pydantic model introspection
            model_fields = getattr(obj, '__fields__', getattr(obj, 'model_fields', {}))
            for field_name in model_fields:
                val = getattr(obj, field_name, None)
                if val is not None:
                    setattr(obj, field_name, _deep_walk(val, op))
            return obj
        return obj
    return _deep_walk(obj, 'encode')
