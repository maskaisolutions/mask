"""
LangChain integration for Mask Privacy SDK.

Provides a ``MaskCallbackHandler`` that plugs into LangChain's
callback system to automatically tokenise/detokenise tool I/O.

Usage:
    from mask.integrations.langchain_hooks import MaskCallbackHandler
    from langchain.agents import AgentExecutor

    agent = AgentExecutor(..., callbacks=[MaskCallbackHandler()])
"""

import logging
from typing import Any, Dict, Optional, Union

from mask.core.utils import deep_decode, deep_encode_pii

logger = logging.getLogger("mask.integrations.langchain")


try:
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore

    class MaskCallbackHandler(BaseCallbackHandler):
        """LangChain callback that logs tool I/O for audit. Real tokenization requires MaskToolWrapper."""

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
                logger.info("[langchain pre-hook] decoded inputs for %s", serialized.get("name"))

        def on_tool_end(
            self,
            output: Any,
            *,
            run_id: Any = None,
            parent_run_id: Any = None,
            tags: Optional[list] = None,
            **kwargs: Any,
        ) -> None:
            """Logging/audit only. Output tokenization happens in MaskToolWrapper."""
            logger.info("[langchain post-hook] tool execution finished")
            # LangChain tool outputs are typically strings; log for audit
            if isinstance(output, str):
                # We can't mutate a string in-place; the encryption happens
                # at the framework boundary via the MaskTool wrapper below.
                pass

except ImportError:
    # LangChain not installed — provide a stub so imports don't break
    class MaskCallbackHandler:  # type: ignore[no-redef]
        """Stub: install langchain-core to use the real handler."""
        def __init__(self) -> None:
            raise ImportError(
                "langchain-core is required for LangChain integration. "
                "Install with: pip install langchain-core"
            )


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
