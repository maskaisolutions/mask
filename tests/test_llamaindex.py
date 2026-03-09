"""Unit tests for the LlamaIndex integration hooks."""

import os
from unittest import mock

import pytest

from mask.core.vault import encode, reset_vault
from mask.integrations.llamaindex_hooks import (
    MaskToolWrapper,
    MaskCallbackHandler,
)

try:
    from llama_index.core.callbacks.schema import CBEventType
except ImportError:
    # Stub it for the CI
    class CBEventType: # type: ignore
        FUNCTION_CALL = "function_call"

# Force memory vault for all tests
os.environ["MASK_VAULT_TYPE"] = "memory"


@pytest.fixture(autouse=True)
def _fresh_vault():
    reset_vault()
    yield
    reset_vault()


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
        
        # Simulated Llamaindex payload
        payload = {"args": {"email": token}}
        
        # 1. Start event (should decode)
        handler.on_event_start(
            event_type=CBEventType.FUNCTION_CALL,
            payload=payload,
            event_id="evt_1"
        )
        
        assert payload["args"]["email"] == "john.smith@gmail.com"
        
        # 2. Simulate LLM updating payload inside the tool
        payload["response"] = {"leaked_email": "john.smith@gmail.com"}
        
        # 3. End event (should encode new leaked emails)
        handler.on_event_end(
            event_type=CBEventType.FUNCTION_CALL,
            payload=payload,
            event_id="evt_1"
        )
        
        assert payload["response"]["leaked_email"] != "john.smith@gmail.com"
        assert payload["response"]["leaked_email"].endswith("@email.com")
