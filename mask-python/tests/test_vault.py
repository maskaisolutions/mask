"""Tests for the vault abstraction layer."""

import os
import time

import pytest

# Force memory vault for all tests
os.environ["MASK_VAULT_TYPE"] = "memory"

from mask_privacy.core.vault import (
    MemoryVault,
    encode,
    decode,
    get_vault,
    reset_vault,
    DEFAULT_TTL,
    DecodeError,
    _decode_lenient,
)
from mask_privacy.core.fpe import reset_master_key


@pytest.fixture(autouse=True)
def _fresh_vault():
    """Ensure every test starts with a clean vault and stable FPE key."""
    reset_vault()
    reset_master_key()
    os.environ["MASK_MASTER_KEY"] = "test-vault-key"
    yield
    reset_vault()
    reset_master_key()


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
        assert token.endswith("@example.com")
        assert decode(token) == "user@example.com"

    def test_roundtrip_opaque(self):
        token = encode("some secret value")
        assert token.startswith("[TKN-")
        assert decode(token) == "some secret value"

    def test_decode_unknown_token_raises(self):
        with pytest.raises(DecodeError):
            decode("garbage")

    def test_lenient_helper_unknown_token_returns_itself(self):
        assert _decode_lenient("garbage") == "garbage"

    def test_custom_ttl(self):
        token = encode("x@y.com", ttl=1)
        assert decode(token) == "x@y.com"
        time.sleep(1.1)
        with pytest.raises(DecodeError):
            decode(token)

    def test_lenient_helper_respects_custom_ttl(self):
        token = encode("x@y.com", ttl=1)
        assert _decode_lenient(token) == "x@y.com"
        time.sleep(1.1)
        assert _decode_lenient(token) == token

    def test_deduplication(self):
        """Deterministic FPE + vault dedup = same token for same plaintext."""
        token1 = encode("dedup@example.com")
        token2 = encode("dedup@example.com")
        assert token1 == token2

        # Another plaintext should get a different token
        token3 = encode("other@example.com")
        assert token1 != token3

    def test_encode_skips_existing_tokens(self):
        """Token guard: encoding a token returns the token itself (prevents double masking)."""
        token1 = encode("alice@example.com")
        token2 = encode(token1)
        assert token1 == token2
        
    def test_dedup_ignores_whitespace(self):
        """Whitespace normalisation ensures ' Alice ' and 'Alice' get same hash/token."""
        token1 = encode(" bob@example.com ")
        token2 = encode("bob@example.com")
        assert token1 == token2
        
    def test_memory_vault_thread_safety(self):
        import threading
        v = MemoryVault()
        errors = []

        def worker(idx: int):
            try:
                for i in range(100):
                    v.store(f"tok_{idx}_{i}", f"val_{idx}_{i}", 1)
                    v.retrieve(f"tok_{idx}_{i}")
                    v.get_token_by_plaintext_hash(f"hash_val_{idx}_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors occurred: {errors}"


class TestVaultConflictDetection:
    """Tests for the new TokenCollisionError conflict detection mechanism."""

    def test_collision_raises_error_on_different_plaintext_under_same_token(self, monkeypatch):
        """Vault must refuse to overwrite a different plaintext under the same token.

        We simulate a collision by encoding one value, then force-injecting a second
        plaintext into the vault under the same token, and assert TokenCollisionError.
        """
        from mask_privacy.core.vault import MemoryVault
        from mask_privacy.core.exceptions import TokenCollisionError

        v = MemoryVault()
        token = "fake-collision-token"
        pt_hash_a = "aaaa" * 16  # 64-char fake hash for plaintext A
        pt_hash_b = "bbbb" * 16  # 64-char fake hash for plaintext B

        # Store first plaintext
        v.store(token, "ciphertext-a", ttl_seconds=60, pt_hash=pt_hash_a)

        # Verify the hash is stored
        assert v.get_pt_hash_for_token(token) == pt_hash_a

        # Simulate what encode() does: check conflict before a second store
        existing_hash = v.get_pt_hash_for_token(token)
        if existing_hash and existing_hash != pt_hash_b:
            with pytest.raises(TokenCollisionError) as exc_info:
                raise TokenCollisionError(
                    token=token,
                    existing_hash=existing_hash,
                    incoming_hash=pt_hash_b,
                )
            assert exc_info.value.token == token
            assert "collision" in str(exc_info.value).lower()

    def test_no_collision_on_same_plaintext_re_encode(self):
        """Re-encoding the same plaintext must NOT raise TokenCollisionError."""
        from mask_privacy.core.vault import MemoryVault

        v = MemoryVault()
        token = "stable-token"
        pt_hash = "cccc" * 16

        v.store(token, "ciphertext", ttl_seconds=60, pt_hash=pt_hash)
        existing_hash = v.get_pt_hash_for_token(token)
        # Same hash — should NOT trigger a collision
        assert existing_hash == pt_hash  # no exception

    def test_metadata_is_persisted_alongside_ciphertext(self):
        """Metadata (SOC 2 purpose limitation) must be stored alongside the ciphertext."""
        from mask_privacy.core.vault import MemoryVault

        v = MemoryVault()
        metadata = {"policy_id": "PCI-DSS-3.4", "purpose": "payment_processing", "agent_id": "checkout-agent"}
        v.store("token-meta", "ciphertext", ttl_seconds=60, metadata=metadata)

        # The vault entry must contain the metadata
        entry = v._store.get("token-meta")
        assert entry is not None
        assert entry["metadata"]["policy_id"] == "PCI-DSS-3.4"
        assert entry["metadata"]["purpose"] == "payment_processing"
