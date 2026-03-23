import os
import pytest
from unittest.mock import patch, MagicMock
from mask_privacy.client import MaskClient, DecodeError

def test_fail_shut_security_enforcement():
    """
    Verify that if MASK_STRICT_PROD is true, decryption failure raises DecodeError
    instead of returning the original token.
    """
    with patch.dict(os.environ, {"MASK_STRICT_PROD": "true"}):
        client = MaskClient()
        
        # Mock retrieve to return a token that will fail decryption (or just mock retrieve to return None)
        # Actually, decode calls retrieve and if it returns None it raises anyway.
        # Let's mock the crypto engine to fail.
        
        with patch.object(client._vault, "retrieve", return_value="some-ciphertext"):
            with patch.object(client._crypto, "decrypt", side_effect=Exception("Decryption failed")):
                with pytest.raises(DecodeError) as exc:
                    client.decode("MASK-123")
                assert "Decryption failed" in str(exc.value)

def test_fail_open_in_dev_mode():
    """
    Verify that if MASK_STRICT_PROD is not true, decryption failure returns the original token (legacy behavior).
    """
    with patch.dict(os.environ, {"MASK_STRICT_PROD": "false"}):
        client = MaskClient()
        
        token = "MASK-123"
        with patch.object(client._vault, "retrieve", return_value="some-ciphertext"):
            with patch.object(client._crypto, "decrypt", side_effect=Exception("Decryption failed")):
                result = client.decode(token)
                assert result == token
