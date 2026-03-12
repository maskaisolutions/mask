"""Unit tests for the LangChain integration hooks."""

import os
import warnings
from unittest import mock

import pytest

from mask.core.vault import encode, decode, MemoryVault, reset_vault
from mask.core.fpe import reset_master_key
from mask.integrations.langchain_hooks import (
    MaskToolWrapper,
    MaskCallbackHandler,
    mask_langchain_hooks,
    secure_tool,
)

# Force memory vault for all tests
os.environ["MASK_VAULT_TYPE"] = "memory"


@pytest.fixture(autouse=True)
def _fresh_vault():
    reset_vault()
    reset_master_key()
    os.environ["MASK_MASTER_KEY"] = "test-langchain-key"
    yield
    reset_vault()
    reset_master_key()


class TestLangchainMaskToolWrapper:

    def test_wrapper_detokenizes_inputs_and_tokenizes_outputs(self):
        token = encode("user@example.com")

        def mock_tool(email: str, subject: str) -> dict:
            assert email == "user@example.com"
            assert subject == "Welcome"
            return {"target": email, "subject": subject}

        secure = MaskToolWrapper(mock_tool)
        result = secure(email=token, subject="Welcome")

        assert result["target"] != "user@example.com"
        assert result["target"].endswith("@email.com")


class TestLangchainMaskCallbackHandler:

    def test_on_tool_start_mutates_inputs(self):
        handler = MaskCallbackHandler()

        token1 = encode("alice@corp.io")
        token2 = encode("bob@corp.io")

        inputs_dict = {
            "primary": token1,
            "cc": [token2, "charlie@corp.io"],
        }

        handler.on_tool_start(
            serialized={"name": "send_email"},
            input_str="...",
            inputs=inputs_dict,
        )

        assert inputs_dict["primary"] == "alice@corp.io"
        assert inputs_dict["cc"][0] == "bob@corp.io"
        assert inputs_dict["cc"][1] == "charlie@corp.io"


class TestLangchainSecureTool:

    def test_secure_tool_decorator_detokenizes_and_retokenizes(self):
        token = encode("dev@mask.ai")

        @secure_tool
        def send_email(email: str, body: str) -> str:
            """Send an email."""
            assert email == "dev@mask.ai"
            return f"Sent to {email}"

        result = send_email(email=token, body="Hello")
        assert "dev@mask.ai" not in result
        assert "@email.com" in result

    def test_secure_tool_preserves_non_pii(self):
        @secure_tool
        def greet(name: str) -> str:
            """Say hello."""
            return f"Hello, {name}!"

        result = greet(name="World")
        assert result == "Hello, World!"

    def test_secure_tool_with_custom_name(self):
        @secure_tool(name="custom_lookup")
        def lookup(user_id: str) -> dict:
            """Find a user."""
            return {"id": user_id}

        assert lookup.__name__ == "custom_lookup"


class TestLangchainMagicHooks:

    def test_mask_langchain_hooks_emits_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with mask_langchain_hooks():
                pass
            assert any(issubclass(x.category, DeprecationWarning) for x in w)

    def test_mask_langchain_hooks_patches_basetool(self):
        from langchain_core.tools import tool

        @tool
        def mock_tool(val: str) -> str:
            """A sample tool for testing."""
            return f"Result: {val}"

        token = encode("secret@mask.ai")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with mask_langchain_hooks():
                result = mock_tool.run(token)

                assert "secret@mask.ai" not in result
                assert "Result:" in result
                assert result.endswith("@email.com")
