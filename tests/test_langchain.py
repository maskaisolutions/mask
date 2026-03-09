"""Unit tests for the LangChain integration hooks."""

import os
from unittest import mock

import pytest

from mask.core.vault import encode, decode, MemoryVault, reset_vault
from mask.integrations.langchain_hooks import (
    MaskToolWrapper,
    MaskCallbackHandler,
)

# Force memory vault for all tests
os.environ["MASK_VAULT_TYPE"] = "memory"


@pytest.fixture(autouse=True)
def _fresh_vault():
    reset_vault()
    yield
    reset_vault()


class TestLangchainMaskToolWrapper:
    
    def test_wrapper_detokenizes_inputs_and_tokenizes_outputs(self):
        # 1. Setup raw tool and tokens
        token = encode("user@example.com")
        
        def mock_tool(email: str, subject: str) -> dict:
            # Inside the tool, it should see plaintext
            assert email == "user@example.com"
            assert subject == "Welcome"
            return {"target": email, "subject": subject}
            
        # 2. Wrap it
        secure_tool = MaskToolWrapper(mock_tool)
        
        # 3. Execute with tokens
        result = secure_tool(email=token, subject="Welcome")
        
        # 4. Assert output got tokenized because it contains the raw email
        assert result["target"] != "user@example.com"
        assert result["target"].endswith("@email.com")
        
        
class TestLangchainMaskCallbackHandler:

    def test_on_tool_start_mutates_inputs(self):
        handler = MaskCallbackHandler()
        
        token1 = encode("alice@corp.io")
        token2 = encode("bob@corp.io")
        
        # Simulated LangChain `inputs` dict
        inputs_dict = {
            "primary": token1,
            "cc": [token2, "charlie@corp.io"]
        }
        
        # Action
        handler.on_tool_start(
            serialized={"name": "send_email"},
            input_str="...", 
            inputs=inputs_dict
        )
        
        # The dictionary should be mutated in place
        assert inputs_dict["primary"] == "alice@corp.io"
        assert inputs_dict["cc"][0] == "bob@corp.io"
        assert inputs_dict["cc"][1] == "charlie@corp.io" # untouched since it wasn't a token
