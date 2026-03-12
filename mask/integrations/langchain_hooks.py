"""
LangChain integration for Mask Privacy SDK.

Provides:
  - ``MaskCallbackHandler`` — plugs into LangChain's callback system.
  - ``MaskToolWrapper``     — wraps any callable for auto-encode/decode.
  - ``secure_tool``         — drop-in decorator that replaces @tool with
                              automatic JIT detokenisation.
  - ``mask_langchain_hooks`` — (deprecated) monkey-patch context manager.

Usage (recommended):
    from mask.integrations.langchain_hooks import secure_tool

    @secure_tool
    def send_email(email_address: str, body: str) -> str:
        '''Send an email.'''
        ...
"""

import logging
import warnings
import functools
from typing import Any, Dict, Optional, Union

from mask.core.utils import deep_decode, deep_encode_pii

logger = logging.getLogger("mask.integrations.langchain")


# Callback handler (for LangChain's callback system)

try:
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore

    class MaskCallbackHandler(BaseCallbackHandler):
        """LangChain callback that logs tool I/O for audit.

        Real tokenisation requires ``MaskToolWrapper`` or ``@secure_tool``.
        """

        name = "MaskPrivacyHandler"

        def on_tool_start(
            self,
            serialized: Dict[str, Any],
            input_str: str,
            *,
            run_id: Any = None,
            parent_run_id: Any = None,
            tags: Optional[list] = None,
            metadata: Optional[Dict[str, Any]] = None,
            inputs: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> None:
            """Detokenise tool inputs before execution."""
            if inputs is not None:
                decoded = deep_decode(inputs)
                inputs.update(decoded)
                logger.info(
                    "[langchain pre-hook] decoded inputs for %s",
                    serialized.get("name"),
                )

        def on_tool_end(
            self,
            output: Any,
            *,
            run_id: Any = None,
            parent_run_id: Any = None,
            tags: Optional[list] = None,
            **kwargs: Any,
        ) -> None:
            """Logging/audit only."""
            logger.info("[langchain post-hook] tool execution finished")

except ImportError:
    class MaskCallbackHandler:  # type: ignore[no-redef]
        """Stub: install langchain-core to use the real handler."""

        def __init__(self) -> None:
            raise ImportError(
                "langchain-core is required for LangChain integration. "
                "Install with: pip install langchain-core"
            )


# Tool wrapper (explicit, works with any callable)

class MaskToolWrapper:
    """Wrap any callable tool to auto-decode inputs and encode outputs.

    Usage with LangChain:
        from langchain.tools import Tool
        from mask.integrations.langchain_hooks import MaskToolWrapper

        raw_tool = lambda email, msg: send_email(email, msg)
        secure_tool = Tool(
            name="send_email",
            func=MaskToolWrapper(raw_tool),
            description="Send an email securely",
        )
    """

    def __init__(self, func: Any) -> None:
        self._func = func

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        decoded_args = tuple(deep_decode(a) for a in args)
        decoded_kwargs = deep_decode(kwargs)
        result = self._func(*decoded_args, **decoded_kwargs)
        return deep_encode_pii(result) if isinstance(result, (str, dict, list)) else result


# @secure_tool decorator — the recommended drop-in replacement

def secure_tool(func=None, *, name: Optional[str] = None, description: Optional[str] = None):
    """Drop-in decorator that wraps a function with Mask JIT detokenisation.

    Can be used bare or with arguments::

        @secure_tool
        def send_email(email: str, body: str) -> str: ...

        @secure_tool(name="lookup_user")
        def find_user(user_id: str) -> dict: ...

    The decorated function will:
      1. Detokenise all token-shaped arguments before calling the original.
      2. Tokenise any PII in the return value before it reaches the LLM.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            decoded_args = tuple(deep_decode(a) for a in args)
            decoded_kwargs = deep_decode(kwargs)
            result = fn(*decoded_args, **decoded_kwargs)
            if isinstance(result, (str, dict, list)):
                return deep_encode_pii(result)
            return result

        # Preserve custom name/description for LangChain tool registration
        if name:
            wrapper.__name__ = name
        if description:
            wrapper.__doc__ = description
        return wrapper

    # Support both @secure_tool and @secure_tool(...)
    if func is not None:
        return decorator(func)
    return decorator


# mask_langchain_hooks — DEPRECATED monkey-patch context manager

import contextlib
from unittest.mock import patch


@contextlib.contextmanager
def mask_langchain_hooks():
    """Context manager for 'magic' LangChain PII protection.

    .. deprecated:: 0.3.0
        Use ``@secure_tool`` or ``MaskToolWrapper`` instead.
        Monkey-patching ``BaseTool.run`` is fragile and hard to debug.

    While active, this hook intercepts all tool calls within LangChain's
    ``BaseTool`` class to automatically detokenize inputs and re-tokenize
    outputs.
    """
    warnings.warn(
        "mask_langchain_hooks() is deprecated and will be removed in v1.0. "
        "Use @secure_tool or MaskToolWrapper instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        logger.warning(
            "langchain-core not installed; mask_langchain_hooks will have no effect."
        )
        yield
        return

    original_run = BaseTool.run

    def wrapped_run(self, tool_input: Any, *args, **kwargs):
        decoded_input = deep_decode(tool_input)
        result = original_run(self, decoded_input, *args, **kwargs)
        return deep_encode_pii(result)

    with patch.object(BaseTool, "run", wrapped_run):
        logger.info("[langchain-magic] active: wrapping BaseTool.run")
        yield
