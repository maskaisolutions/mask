"""Tests for the vault abstraction layer."""

import os
import time

import pytest

# Force memory vault for all tests
os.environ["MASK_VAULT_TYPE"] = "memory"

from mask.core.vault import (
    MemoryVault,
    encode,
    decode,
    get_vault,
    reset_vault,
    DEFAULT_TTL,
    DecodeError,
    _decode_lenient,
)


@pytest.fixture(autouse=True)
def _fresh_vault():
    """Ensure every test starts with a clean vault."""
    reset_vault()
    yield
    reset_vault()


class TestMemoryVault:
    def test_store_and_retrieve(self):
        v = MemoryVault()
        v.store("tok1", "hello", ttl_seconds=60)
        assert v.retrieve("tok1") == "hello"

    def test_missing_key_returns_none(self):
        v = MemoryVault()
        assert v.retrieve("nope") is None

    def test_expired_key_returns_none(self):
        v = MemoryVault()
        v.store("tok2", "data", ttl_seconds=0)
        time.sleep(0.05)
        assert v.retrieve("tok2") is None

    def test_delete(self):
        v = MemoryVault()
        v.store("tok3", "val", ttl_seconds=60)
        v.delete("tok3")
        assert v.retrieve("tok3") is None


class TestEncodeDecodePublicAPI:
    def test_roundtrip_email(self):
        token = encode("user@example.com")
        assert token.endswith("@email.com")
        assert decode(token) == "user@example.com"

    def test_roundtrip_opaque(self):
        token = encode("some secret value")
        assert token.startswith("[TKN-")
        assert decode(token) == "some secret value"

    def test_decode_unknown_token_returns_itself(self):
        # Strict decode now raises when token cannot be resolved
        with pytest.raises(DecodeError):
            decode("garbage")

    def test_lenient_helper_unknown_token_returns_itself(self):
        # Legacy behaviour preserved via internal helper
        assert _decode_lenient("garbage") == "garbage"

    def test_custom_ttl(self):
        token = encode("x@y.com", ttl=1)
        assert decode(token) == "x@y.com"
        time.sleep(1.1)
        # Strict decode raises once the token has expired
        with pytest.raises(DecodeError):
            decode(token)

    def test_lenient_helper_respects_custom_ttl(self):
        token = encode("x@y.com", ttl=1)
        assert _decode_lenient(token) == "x@y.com"
        time.sleep(1.1)
        # After expiry, lenient helper falls back to returning the token
        assert _decode_lenient(token) == token

    def test_deduplication(self):
        token1 = encode("dedup@example.com")
        token2 = encode("dedup@example.com")
        assert token1 == token2
        
        # Another plaintext should get a different token
        token3 = encode("other@example.com")
        assert token1 != token3

    def test_memory_vault_thread_safety(self):
        import threading
        v = MemoryVault()
        errors = []
        
        def worker(idx: int):
            try:
                for i in range(100):
                    v.store(f"tok_{idx}_{i}", f"val_{idx}_{i}", 1)
                    v.retrieve(f"tok_{idx}_{i}")
                    v.get_token_by_plaintext_hash(f"hash_" + f"val_{idx}_{i}")
            except Exception as e:
                errors.append(e)
                
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        assert not errors, f"Thread safety errors occurred: {errors}"
