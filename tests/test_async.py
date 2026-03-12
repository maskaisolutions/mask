"""Tests for the async wrappers."""

import os
import asyncio
import pytest

from mask.core.vault import encode, decode, aencode, adecode, reset_vault
from mask.core.fpe import looks_like_token, reset_master_key
from mask.client import MaskClient


@pytest.fixture(autouse=True)
def _fresh_vault():
    os.environ["MASK_VAULT_TYPE"] = "memory"
    reset_vault()
    reset_master_key()
    os.environ["MASK_MASTER_KEY"] = "test-async-key"
    yield
    reset_vault()
    reset_master_key()


@pytest.mark.asyncio
async def test_module_level_async_wrappers():
    """Test aencode and adecode from vault.py."""
    token = await aencode("test@async.com")
    assert looks_like_token(token)
    assert token.endswith("@email.com")

    plaintext = await adecode(token)
    assert plaintext == "test@async.com"


@pytest.mark.asyncio
async def test_client_async_wrappers():
    """Test aencode, adecode, and ascan_and_tokenize from MaskClient."""
    client = MaskClient()
    
    # 1. Test encoding
    token = await client.aencode("client@async.com")
    assert looks_like_token(token)
    
    # 2. Test decoding
    plaintext = await client.adecode(token)
    assert plaintext == "client@async.com"
    
    # 3. Test scanning
    text = "Contact me at bob@example.com"
    safe_text = await client.ascan_and_tokenize(text)
    assert "bob@example.com" not in safe_text
    assert "tkn-" in safe_text
    assert safe_text.endswith("@email.com")
