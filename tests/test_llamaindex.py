"""Unit tests for the LlamaIndex integration hooks."""

import os
from unittest import mock

import pytest

from mask.core.vault import encode, reset_vault
from mask.core.fpe import reset_master_key
from mask.integrations.llamaindex_hooks import (
    MaskToolWrapper,
    MaskCallbackHandler,
    mask_llamaindex_hooks,
)

try:
    from llama_index.core.callbacks.schema import CBEventType
except ImportError:
    # Stub it for CI
    class CBEventType:  # type: ignore
        FUNCTION_CALL = "function_call"

# Force memory vault for all tests
os.environ["MASK_VAULT_TYPE"] = "memory"


@pytest.fixture(autouse=True)
def _fresh_vault():
    reset_vault()
    reset_master_key()
    os.environ["MASK_MASTER_KEY"] = "test-llamaindex-key"
    yield
    reset_vault()
    reset_master_key()


class TestLlamaindexMaskToolWrapper:

    def test_wrapper_detokenizes_inputs_and_tokenizes_outputs(self):
        token = encode("admin@hospital.com")

        def test_query(email: str, prompt: str) -> dict:
            assert email == "admin@hospital.com"
            assert prompt == "Give me the records"
            return {"target": email, "status": "success"}

        secure_tool = MaskToolWrapper(test_query)
        result = secure_tool(email=token, prompt="Give me the records")

        assert result["target"] != "admin@hospital.com"
        assert result["target"].endswith("@email.com")


class TestLlamaindexMaskCallbackHandler:

    def test_on_event_start_and_end_mutates_payload(self):
        handler = MaskCallbackHandler()

        token = encode("john.smith@gmail.com")
        payload = {"args": {"email": token}}

        handler.on_event_start(
            event_type=CBEventType.FUNCTION_CALL,
            payload=payload,
            event_id="evt_1",
        )

        assert payload["args"]["email"] == "john.smith@gmail.com"

        payload["response"] = {"leaked_email": "john.smith@gmail.com"}

        handler.on_event_end(
            event_type=CBEventType.FUNCTION_CALL,
            payload=payload,
            event_id="evt_1",
        )

        assert payload["response"]["leaked_email"] != "john.smith@gmail.com"
        assert payload["response"]["leaked_email"].endswith("@email.com")


class TestLlamaindexMagicHooks:

    def test_mask_llamaindex_hooks_patches_basetool(self):
        from llama_index.core.tools import FunctionTool

        def mock_fn(val: str) -> str:
            return f"Secret: {val}"

        secure_tool = FunctionTool.from_defaults(fn=mock_fn, name="mock")
        token = encode("llamaindex@mask.ai")

        with mask_llamaindex_hooks():
            result = secure_tool(token)

            assert "llamaindex@mask.ai" not in str(result)
            assert "Secret:" in str(result)
            assert "tkn-" in str(result)
