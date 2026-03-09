"""
Core cryptography engine for Mask SDK.

Provides a CryptoEngine singleton that handles Envelope Encryption,
ensuring that plaintext PII is encrypted locally before being
transmitted and stored in distributed vaults (Redis/Memcached/DynamoDB).

Requires MASK_ENCRYPTION_KEY to be set in the environment.
"""

import os
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
    """Handles symmetric encryption for vault payloads."""
    
    _instance: Optional["CryptoEngine"] = None

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
        """Initialise the underlying Fernet engine.

        In all environments (including production and staging), a persistent
        MASK_ENCRYPTION_KEY **must** be configured. We intentionally do not
        fall back to an ephemeral key here, because that would make tokens
        non-recoverable across process restarts and break auditability.
        """
        key = os.environ.get("MASK_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError(
                "MASK_ENCRYPTION_KEY is not set. "
                "Generate a Fernet key with:\n"
                "  from cryptography.fernet import Fernet\n"
                "  print(Fernet.generate_key().decode('utf-8'))\n"
                "and export it as MASK_ENCRYPTION_KEY before starting your agent."
            )

        try:
            self._fernet = Fernet(key.encode("utf-8"))
        except ValueError as e:
            raise ValueError(
                "Invalid MASK_ENCRYPTION_KEY. Must be a valid url-safe base64-encoded "
                "Fernet key. Use `cryptography.fernet.Fernet.generate_key()` to create one."
            ) from e

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext into a url-safe base64 string."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt url-safe base64 ciphertext back to plaintext."""
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logger.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY.")
            raise ValueError("Decryption failed") from e


def get_crypto_engine() -> CryptoEngine:
    """Return the configured crypto engine singleton."""
    return CryptoEngine()
