"""
LangChain integration for Mask Privacy SDK.

Provides:
  - ``MaskCallbackHandler`` — plugs into LangChain's callback system.
  - ``MaskToolWrapper``     — wraps any callable for auto-encode/decode.
  - ``secure_tool``         — drop-in decorator that replaces @tool with
                              automatic JIT detokenisation.

Usage (recommended):
    from mask_privacy.integrations.langchain_hooks import secure_tool

    @secure_tool
    def send_email(email_address: str, body: str) -> str:
        '''Send an email.'''
        ...
"""

import logging
import functools
from typing import Any, Dict, Optional, Union

from ..core.utils import deep_decode, deep_encode_pii

logger = logging.getLogger("mask.integrations.langchain")


# Callback handler (for LangChain's callback system)

try:
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore

    class MaskCallbackHandler(BaseCallbackHandler):
        """LangChain callback that logs tool I/O for audit.

        Real tokenisation requires ``MaskToolWrapper`` or ``@secure_tool``.
        """

        name = "MaskPrivacyHandler"

        def __init__(self, client: Any = None, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self._client = client

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
            """Log tool inputs for audit — does NOT mutate the original inputs.

            Actual detokenisation is handled by MaskToolWrapper / @secure_tool.
            """
            if inputs is not None:
                # Work on a copy for audit/logging — do NOT mutate the original
                decoded_copy = deep_decode(dict(inputs), client=self._client)
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
        from mask_privacy.integrations.langchain_hooks import MaskToolWrapper

        raw_tool = lambda email, msg: send_email(email, msg)
        secure_tool = Tool(
            name="send_email",
            func=MaskToolWrapper(raw_tool),
            description="Send an email securely",
        )
    """

    def __init__(self, func: Any, client: Any = None) -> None:
        self._func = func
        self._client = client

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        decoded_args = tuple(deep_decode(a, client=self._client) for a in args)
        decoded_kwargs = deep_decode(kwargs, client=self._client)
        result = self._func(*decoded_args, **decoded_kwargs)
        return deep_encode_pii(result, client=self._client) if isinstance(result, (str, dict, list)) else result


# @secure_tool decorator — the recommended drop-in replacement

def secure_tool(func=None, *, name: Optional[str] = None, description: Optional[str] = None, client: Any = None):
    """Drop-in decorator that wraps a function with Mask JIT detokenisation.

    Can be used bare or with arguments::

        @secure_tool
        def send_email(email: str, body: str) -> str: ...

        @secure_tool(name="lookup_user", client=my_client)
        def find_user(user_id: str) -> dict: ...

    The decorated function will:
      1. Detokenise all token-shaped arguments before calling the original.
      2. Tokenise any PII in the return value before it reaches the LLM.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            decoded_args = tuple(deep_decode(a, client=client) for a in args)
            decoded_kwargs = deep_decode(kwargs, client=client)
            result = fn(*decoded_args, **decoded_kwargs)
            if isinstance(result, (str, dict, list)):
                return deep_encode_pii(result, client=client)
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

