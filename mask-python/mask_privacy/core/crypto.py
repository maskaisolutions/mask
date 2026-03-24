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
import base64
import secrets
import threading
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise ImportError(
        "The 'cryptography' package is required for Mask. "
        "Install with: pip install cryptography"
    )

logger = logging.getLogger("mask.crypto")

AES_GCM_PREFIX = "aes:"

class CryptoEngine:
    """Handles symmetric encryption for vault payloads and blind indexing."""
    
    _instance: Optional["CryptoEngine"] = None
    _aesgcm: Optional[AESGCM] = None
    _index_secret: Optional[bytes] = None
    _lock = threading.Lock()

    def __new__(cls) -> "CryptoEngine":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Clear the singleton instance to force re-initialization (useful for key rotation)."""
        cls._instance = None

    def _init(self) -> None:
        """Initialize the underlying AES-GCM engine and index secrets.

        The encryption key is retrieved from the active ``KeyProvider``.
        If no key is available, a throwaway key is auto-generated ONLY
        when ``MASK_DEV_MODE=true`` is explicitly set.
        """
        from mask_privacy.core.key_provider import get_key_provider

        provider = get_key_provider()
        key = provider.get_encryption_key()
        if not key:
            if os.environ.get("MASK_DEV_MODE") == "true":
                key = secrets.token_hex(32)
                os.environ["MASK_ENCRYPTION_KEY"] = key
                logger.warning(
                    "MASK_DEV_MODE is enabled. Using a generated throwaway key. "
                    "DO NOT USE THIS IN PRODUCTION — tokens will be lost on restart."
                )
            else:
                from mask_privacy.core.exceptions import MaskSecurityError
                raise MaskSecurityError(
                    "MASK_ENCRYPTION_KEY is not set. Set MASK_ENCRYPTION_KEY to a valid "
                    "secret, or set MASK_DEV_MODE=true to use an ephemeral throwaway key."
                )

        try:
            # Derive the 32-byte key equivalent to TS: cryptoNode.createHash('sha256').update(key).digest()
            aes_key = hashlib.sha256(key.encode("utf-8")).digest()
            self._aesgcm = AESGCM(aes_key)
        except ValueError as e:
            raise ValueError(
                "Failed to initialize AES-GCM engine with the provided key."
            ) from e

        # Derive a separate secret for blind indexing (HMAC-SHA256)
        # We derive it from the master encryption key so we don't need a 3rd env var.
        master_key = provider.get_master_key() or key
        salt = os.environ.get("MASK_BLIND_INDEX_SALT", "mask-blind-index").encode()
        self._index_secret = hmac.new(
            master_key.encode("utf-8"), salt, hashlib.sha256
        ).digest()

    def get_index_secret(self) -> bytes:
        """Return the secret used for HMAC-based blind indexing."""
        if self._index_secret is None:
            raise RuntimeError("CryptoEngine not initialized. No index secret available.")
        return self._index_secret

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext into a base64 AES-GCM string."""
        aesgcm = self._aesgcm
        if aesgcm is None:
            raise RuntimeError("CryptoEngine not initialized. AES-GCM engine missing.")
        
        iv = os.urandom(12)
        # AESGCM.encrypt puts the auth tag (16 bytes) at the end of the ciphertext
        ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        
        # TS wire format expects: iv (12) + authTag (16) + ciphertext
        tag = ciphertext_and_tag[-16:]
        encrypted_text = ciphertext_and_tag[:-16]
        
        combined = iv + tag + encrypted_text
        return AES_GCM_PREFIX + base64.b64encode(combined).decode("utf-8")

    def _decrypt_legacy_fernet(self, ciphertext: str) -> str:
        """Fallback for tokens encrypted with the legacy Fernet implementation."""
        from cryptography.fernet import Fernet
        from mask_privacy.core.key_provider import get_key_provider
        
        provider = get_key_provider()
        key = provider.get_encryption_key()
        if not key:
            raise ValueError("No encryption key available for Fernet fallback.")
            
        fernet = Fernet(key.encode("utf-8"))
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt base64 AES-GCM ciphertext back to plaintext."""
        aesgcm = self._aesgcm
        if aesgcm is None:
            raise RuntimeError("CryptoEngine not initialized. AES-GCM engine missing.")
            
        try:
            if not ciphertext.startswith(AES_GCM_PREFIX):
                # Attempt legacy Fernet decryption
                return self._decrypt_legacy_fernet(ciphertext)
                
            b64_data = ciphertext.removeprefix(AES_GCM_PREFIX)
            combined = base64.b64decode(b64_data)
            
            # TS wire format: iv (12) + authTag (16) + ciphertext
            iv = combined[0:12]
            tag = combined[12:28]
            encrypted_text = combined[28:len(combined)]
            
            # Python AESGCM expects: ciphertext + authTag
            python_format_ciphertext = encrypted_text + tag
            
            return aesgcm.decrypt(iv, python_format_ciphertext, None).decode("utf-8")
        except Exception as e:
            from mask_privacy.core.exceptions import MaskDecryptionError
            logger.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY.")
            raise MaskDecryptionError("Decryption failed") from e


def get_crypto_engine() -> CryptoEngine:
    """Return the configured crypto engine singleton."""
    return CryptoEngine()

