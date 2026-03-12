"""Tests for the dynamic ADK hook system."""

import os

os.environ["MASK_VAULT_TYPE"] = "memory"

import pytest

from mask.core.vault import encode, reset_vault
from mask.core.fpe import reset_master_key
from mask.integrations.adk_hooks import (
    decrypt_before_tool,
    encrypt_after_tool,
)
from mask.core.utils import deep_decode as _deep_decode, deep_encode_pii as _deep_encode_pii
from mask.core.fpe import looks_like_token


# Minimal stubs matching ADK protocol
class _FakeTool:
    name = "test_tool"


class _FakeCtx:
    agent_name = "test_agent"


@pytest.fixture(autouse=True)
def _fresh():
    reset_vault()
    reset_master_key()
    os.environ["MASK_MASTER_KEY"] = "test-hooks-key"
    yield
    reset_vault()
    reset_master_key()


class TestDeepDecode:
    def test_flat_dict(self):
        token = encode("alice@corp.io")
        result = _deep_decode({"email": token, "msg": "hi"})
        assert result["email"] == "alice@corp.io"
        assert result["msg"] == "hi"

    def test_nested_dict(self):
        token = encode("bob@bank.com")
        data = {"user": {"contact": {"email": token}}}
        result = _deep_decode(data)
        assert result["user"]["contact"]["email"] == "bob@bank.com"

    def test_list_values(self):
        t1 = encode("a@b.com")
        t2 = encode("c@d.com")
        result = _deep_decode({"recipients": [t1, t2]})
        assert result["recipients"] == ["a@b.com", "c@d.com"]

    def test_non_token_strings_unchanged(self):
        result = _deep_decode({"name": "Alice", "age": 30})
        assert result == {"name": "Alice", "age": 30}


class TestDeepEncodeEmails:
    def test_encodes_raw_email(self):
        result = _deep_encode_pii({"email": "test@example.com"})
        assert looks_like_token(result["email"])
        assert result["email"].endswith("@email.com")

    def test_does_not_double_encode_token(self):
        token = encode("original@test.com")
        result = _deep_encode_pii({"email": token})
        assert result["email"] == token  # should NOT re-encode


class TestDecryptBeforeTool:
    def test_mutates_args_in_place(self):
        token = encode("admin@secure.io")
        args = {"email": token, "action": "send"}
        decrypt_before_tool(_FakeTool(), args, _FakeCtx())
        assert args["email"] == "admin@secure.io"
        assert args["action"] == "send"


class TestEncryptAfterTool:
    def test_encodes_leaked_emails_in_args(self):
        args = {"email": "leaked@plain.com"}
        encrypt_after_tool(_FakeTool(), args, _FakeCtx(), {})
        assert looks_like_token(args["email"])

    def test_encodes_leaked_emails_in_string_response(self):
        args = "Contact us at support@example.com for help."
        result = _deep_encode_pii(args)
        assert isinstance(result, str)
        assert "@email.com" in result
        assert "support@example.com" not in result

    def test_encodes_leaked_emails_but_skips_tokens_in_nested_dict(self):
        token = encode("admin@secure.io")
        args = {"response": {"leaked": "bad@plain.com", "safe": token}}
        result = _deep_encode_pii(args)
        
        assert looks_like_token(result["response"]["leaked"])
        assert result["response"]["safe"] == token  # Guarded against double masking

