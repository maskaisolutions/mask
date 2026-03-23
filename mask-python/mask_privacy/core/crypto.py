"""
Core cryptography engine for Mask SDK.

Provides a CryptoEngine singleton that handles Envelope Encryption,
ensuring that plaintext PII is encrypted locally before being
transmitted and stored in distributed vaults (Redis/Memcached/DynamoDB).

Requires MASK_ENCRYPTION_KEY to be set in the environment.
"""

import os
import hmac
import hashlib
import logging
from typing import Optional

try:
    from cryptography.fernet import Fernet
except ImportError:
    raise ImportError(
        "The 'cryptography' package is required for Mask. "
        "Install with: pip install cryptography"
    )

logger = logging.getLogger("mask.crypto")

class CryptoEngine:
    """Handles symmetric encryption for vault payloads and blind indexing."""
    
    _instance: Optional["CryptoEngine"] = None
    _fernet: Optional[Fernet] = None
    _index_secret: Optional[bytes] = None

    def __new__(cls) -> "CryptoEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Clear the singleton instance to force re-initialization (useful for key rotation)."""
        cls._instance = None

    def _init(self) -> None:
        """Initialize the underlying Fernet engine and index secrets.

        The encryption key is retrieved from the active ``KeyProvider``.
        If no key is available, a throwaway key is auto-generated for
        local/test/demo use.
        """
        from mask_privacy.core.key_provider import get_key_provider

        provider = get_key_provider()
        key = provider.get_encryption_key()
        if not key:
            if os.environ.get("MASK_STRICT_PROD") == "true":
                from mask_privacy.core.exceptions import MaskSecurityError
                raise MaskSecurityError(
                    "MASK_STRICT_PROD is enabled but MASK_ENCRYPTION_KEY is not set. "
                    "Refusing to start with an auto-generated key in production mode."
                )
            key = Fernet.generate_key().decode("utf-8")
            os.environ["MASK_ENCRYPTION_KEY"] = key
            logger.warning("MASK_ENCRYPTION_KEY not set. Using a generated throwaway key. DO NOT USE THIS IN PRODUCTION.")

        try:
            self._fernet = Fernet(key.encode("utf-8"))
        except ValueError as e:
            raise ValueError(
                "Invalid MASK_ENCRYPTION_KEY. Must be a valid url-safe base64-encoded "
                "Fernet key. Use `cryptography.fernet.Fernet.generate_key()` to create one."
            ) from e

        # Derive a separate secret for blind indexing (HMAC-SHA256)
        # We derive it from the master encryption key so we don't need a 3rd env var.
        master_key = provider.get_master_key() or key
        self._index_secret = hmac.new(
            master_key.encode("utf-8"), b"mask-blind-index", hashlib.sha256
        ).digest()

    def get_index_secret(self) -> bytes:
        """Return the secret used for HMAC-based blind indexing."""
        if self._index_secret is None:
            raise RuntimeError("CryptoEngine not initialized. No index secret available.")
        return self._index_secret

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext into a url-safe base64 string."""
        if self._fernet is None:
            raise RuntimeError("CryptoEngine not initialized. Fernet engine missing.")
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt url-safe base64 ciphertext back to plaintext."""
        if self._fernet is None:
            raise RuntimeError("CryptoEngine not initialized. Fernet engine missing.")
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except Exception as e:
            from mask_privacy.core.exceptions import MaskDecryptionError
            logger.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY.")
            raise MaskDecryptionError("Decryption failed") from e


def get_crypto_engine() -> CryptoEngine:
    """Return the configured crypto engine singleton."""
    return CryptoEngine()
