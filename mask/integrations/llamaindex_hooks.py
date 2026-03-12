"""
LlamaIndex integration for Mask Privacy SDK.

Provides a ``MaskToolSpec`` wrapper and a ``MaskQueryTransform``
that plugs into LlamaIndex's tool and query pipelines to automatically
tokenise/detokenise data flowing through RAG workflows.

Usage:
    from mask.integrations.llamaindex_hooks import MaskToolWrapper
    from llama_index.core.tools import FunctionTool

    raw_fn = lambda email, body: send_email(email, body)
    secure_tool = FunctionTool.from_defaults(fn=MaskToolWrapper(raw_fn), name="send_email")
"""

import logging
from typing import Any, Dict, Optional

from mask.core.utils import deep_decode, deep_encode_pii

logger = logging.getLogger("mask.integrations.llamaindex")

# Tool Wrapper — works with any callable

class MaskToolWrapper:
    """Wrap any callable tool to auto-decode inputs and encode outputs.

    Usage with LlamaIndex:
        from llama_index.core.tools import FunctionTool
        from mask.integrations.llamaindex_hooks import MaskToolWrapper

        def send_email(email: str, body: str) -> str:
            ...

        secure_tool = FunctionTool.from_defaults(
            fn=MaskToolWrapper(send_email),
            name="send_email",
            description="Send an email securely",
        )
    """

    def __init__(self, func: Any) -> None:
        self._func = func
        # Preserve metadata for LlamaIndex introspection
        self.__name__ = getattr(func, "__name__", "mask_wrapped")
        self.__doc__ = getattr(func, "__doc__", "")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        logger.info("[llamaindex pre-hook] decoding tool inputs")
        decoded_args = tuple(deep_decode(a) for a in args)
        decoded_kwargs = deep_decode(kwargs)

        result = self._func(*decoded_args, **decoded_kwargs)

        logger.info("[llamaindex post-hook] encoding tool outputs")
        if isinstance(result, (str, dict, list)):
            return deep_encode_pii(result)
        return result


# Callback handler (for LlamaIndex's callback system)

try:
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler  # type: ignore
    from llama_index.core.callbacks.schema import CBEventType, EventPayload  # type: ignore

    class MaskCallbackHandler(BaseCallbackHandler):
        """LlamaIndex callback that logs privacy events for audit."""

        def __init__(
            self,
            event_starts_to_ignore: Optional[list] = None,
            event_ends_to_ignore: Optional[list] = None,
        ) -> None:
            super().__init__(
                event_starts_to_ignore=event_starts_to_ignore or [],
                event_ends_to_ignore=event_ends_to_ignore or []
            )

        def on_event_start(
            self,
            event_type: CBEventType,
            payload: Optional[Dict[str, Any]] = None,
            event_id: str = "",
            parent_id: str = "",
            **kwargs: Any,
        ) -> str:
            if event_type == CBEventType.FUNCTION_CALL and payload:
                decoded = deep_decode(payload)
                payload.update(decoded)
                logger.info("[llamaindex callback] decoded payload for event %s", event_id)
            return event_id

        def on_event_end(
            self,
            event_type: CBEventType,
            payload: Optional[Dict[str, Any]] = None,
            event_id: str = "",
            **kwargs: Any,
        ) -> None:
            if event_type == CBEventType.FUNCTION_CALL and payload:
                encoded = deep_encode_pii(payload)
                payload.update(encoded)
                logger.info("[llamaindex callback] encoded payload for event %s", event_id)

        def start_trace(self, trace_id: Optional[str] = None) -> None:
            pass

        def end_trace(
            self,
            trace_id: Optional[str] = None,
            trace_map: Optional[Dict[str, list]] = None,
        ) -> None:
            pass

except ImportError:
    # LlamaIndex not installed — provide a stub so imports don't break
    class MaskCallbackHandler:  # type: ignore[no-redef]
        """Stub: install llama-index-core to use the real handler."""
        def __init__(self) -> None:
            raise ImportError(
                "llama-index-core is required for LlamaIndex integration. "
                "Install with: pip install llama-index-core"
            )

import contextlib
from unittest.mock import patch

@contextlib.contextmanager
def mask_llamaindex_hooks():
    """Context manager for 'magic' LlamaIndex PII protection.

    While active, this hook intercepts all tool calls within LlamaIndex's
    BaseTool class (including FunctionTool) to automatically detokenize
    inputs and re-tokenize outputs.
    """
    try:
        from llama_index.core.tools import BaseTool
    except ImportError:
        logger.warning("llama-index-core not installed; mask_llamaindex_hooks will have no effect.")
        yield
        return

    original_call = BaseTool.__call__
    
    def wrapped_call(self, *args, **kwargs):
        # 1. Detokenize inputs
        decoded_args = tuple(deep_decode(a) for a in args)
        decoded_kwargs = deep_decode(kwargs)
        # 2. Execute tool
        result = original_call(self, *decoded_args, **decoded_kwargs)
        # 3. Tokenize output
        if isinstance(result, (str, dict, list)):
            return deep_encode_pii(result)
        return result

    with patch.object(BaseTool, "__call__", wrapped_call):
        logger.info("[llamaindex-magic] active: wrapping BaseTool.__call__")
        yield
