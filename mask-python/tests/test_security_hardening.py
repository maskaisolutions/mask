import os
import pytest
from unittest.mock import patch, MagicMock
from mask_privacy.client import MaskClient
from mask_privacy.core.vault import DecodeError

def test_fail_shut_security_enforcement():
    """
    Verify that when MASK_DEV_MODE is NOT true (default / production),
    decryption failure raises DecodeError instead of returning the original token.
    """
    with patch.dict(os.environ, {"MASK_DEV_MODE": "false"}):
        client = MaskClient()
        
        with patch.object(client.vault, "retrieve", return_value="some-ciphertext"):
            with patch.object(client.crypto, "decrypt", side_effect=Exception("Decryption failed")):
                with pytest.raises(DecodeError) as exc:
                    client.decode("MASK-123")
                assert "Decryption failed" in str(exc.value)

def test_fail_open_in_dev_mode():
    """
    Verify that when MASK_DEV_MODE is true, decryption failure returns the original token.
    """
    with patch.dict(os.environ, {"MASK_DEV_MODE": "true"}):
        client = MaskClient()
        
        token = "MASK-123"
        with patch.object(client.vault, "retrieve", return_value="some-ciphertext"):
            with patch.object(client.crypto, "decrypt", side_effect=Exception("Decryption failed")):
                result = client.decode(token)
                assert result == token


def test_argon2id_kdf_enforcement():
    """
    Verify that the SDK refuses to initialize its CryptoEngine and fails shut
    if the 'argon2-cffi' package is unavailable. This guarantees that modern
    memory-hard KDFs (OWASP 2026) are strictly enforced in all deployments.
    """
    import sys
    from mask_privacy.core.crypto import CryptoEngine

    # Simulate missing dependency
    sys.modules["argon2.low_level"] = None  # type: ignore

    try:
        CryptoEngine._instance = None
        with pytest.raises(ImportError) as exc:
            # We bypass the singleton getter to force a fresh _init() call
            CryptoEngine()
        assert "argon2-cffi" in str(exc.value)
        assert "is required for Mask SDK cryptographic operations" in str(exc.value)
    finally:
        # Restore module state
        CryptoEngine._instance = None
        if "argon2.low_level" in sys.modules:
            del sys.modules["argon2.low_level"]

def test_keyring_key_rotation_aes_v2():
    """
    Verify that the JSON MASK_KEYRING successfully rotates keys.
    The CryptoEngine should encrypt using the "active" (last) key in the keyring,
    and successfully decrypt both the active and historical ciphertexts without data loss.
    """
    from mask_privacy.core.crypto import CryptoEngine
    import json
    
    keyring_payload = json.dumps({
        "v1": "a" * 32,
        "v2": "b" * 32
    })
    
    with patch.dict(os.environ, {"MASK_KEYRING": keyring_payload}):
        CryptoEngine.reset()
        crypto = CryptoEngine()
        
        plaintext = "sensitive_data123"
        
        # 1. Encrypt uses the active (v2) key
        ciphertext_v2 = crypto.encrypt(plaintext)
        assert ciphertext_v2.startswith("aes:v2:v2:")
        
        # 2. Decrypting the current active key works
        decrypted_v2 = crypto.decrypt(ciphertext_v2)
        assert decrypted_v2 == plaintext
        
        # 3. Simulate legacy ciphertext from the older v1 key
        # We temporarily set v1 as active just to generate a valid v1 ciphertext
        crypto._active_key_id = "v1"
        ciphertext_v1 = crypto.encrypt(plaintext)
        assert ciphertext_v1.startswith("aes:v2:v1:")
        
        # Reset back to v2 as active
        crypto._active_key_id = "v2"
        
        # 4. Decrypting the legacy (v1) ciphertext works seamlessly
        decrypted_v1 = crypto.decrypt(ciphertext_v1)
        assert decrypted_v1 == plaintext
        
        CryptoEngine.reset()
