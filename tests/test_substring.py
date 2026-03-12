"""Tests for sub-string detokenization."""

import os
import pytest
from mask.core.vault import encode, reset_vault, detokenize_text
from mask.core.fpe import reset_master_key
from mask.core.utils import deep_decode

@pytest.fixture(autouse=True)
def _fresh_vault():
    os.environ["MASK_VAULT_TYPE"] = "memory"
    reset_vault()
    reset_master_key()
    os.environ["MASK_MASTER_KEY"] = "test-substring-key"
    yield
    reset_vault()
    reset_master_key()

def test_detokenize_text_with_embedded_tokens():
    """Test replacing tokens found inside a paragraph."""
    email = "alice@example.com"
    phone = "+1-555-123-4567"
    
    t_email = encode(email)
    t_phone = encode(phone)
    
    paragraph = f"Contact {t_email} at {t_phone} today."
    restored = detokenize_text(paragraph)
    
    assert email in restored
    assert phone in restored
    assert restored == f"Contact {email} at {phone} today."

def test_deep_decode_handles_paragraphs():
    """Test that deep_decode correctly detokenizes string values containing tokens."""
    email = "bob@work.com"
    t_email = encode(email)
    
    data = {
        "email": t_email,
        "body": f"Hi, I am {t_email}. Please call me.",
        "nested": [f"Token: {t_email}"]
    }
    
    decoded = deep_decode(data)
    
    assert decoded["email"] == email
    assert decoded["body"] == f"Hi, I am {email}. Please call me."
    assert decoded["nested"][0] == f"Token: {email}"

def test_detokenize_text_lenient():
    """Test that unknown tokens are left as-is."""
    bogus = "tkn-12345678@email.com"
    paragraph = f"Hello {bogus}"
    
    restored = detokenize_text(paragraph)
    assert restored == paragraph
