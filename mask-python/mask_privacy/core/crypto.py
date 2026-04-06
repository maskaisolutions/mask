"""
Core cryptography engine for Mask SDK.

Provides a CryptoEngine singleton that handles Envelope Encryption,
ensuring that plaintext PII is encrypted locally before being
transmitted and stored in distributed vaults (Redis/Memcached/DynamoDB).

Supports a JSON-based Keyring for transparent key rotation.
Set MASK_KEYRING='{"v1": "oldkey...", "v2": "newkey..."}' to enable rotation.
The *last* key in the JSON object is the active encryption key.

Legacy single-key mode (MASK_ENCRYPTION_KEY) remains fully supported and
maps to the implicit key ID "default".

Requires MASK_ENCRYPTION_KEY or MASK_KEYRING to be set in the environment.
"""

import os
import json
import hashlib
import logging
import base64
import secrets
import threading
from typing import Optional, Dict
from mask_privacy import config

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise ImportError(
        "The 'cryptography' package is required for Mask. "
        "Install with: pip install cryptography"
    )

logger = logging.getLogger("mask.crypto")

# Envelope prefixes
# aes:v2:{keyId}:{base64}  — current versioned keyring format
# aes:v1:{base64}          — single-key format (key ID = "default")
# aes:{base64}             — oldest legacy format (key ID = "default")
AES_V2_PREFIX = "aes:v2:"
AES_GCM_PREFIX = "aes:v1:"
AES_GCM_LEGACY_PREFIX = "aes:"  # backward-compat for tokens created before key versioning


class CryptoEngine:
    """Handles symmetric encryption for vault payloads and blind indexing.

    Key Rotation:
        Set MASK_KEYRING as a JSON object mapping key IDs to raw key strings.
        The last entry in the JSON object is the active encryption key.
        All listed keys are available for decryption, enabling zero-downtime rotation.

    Legacy mode:
        MASK_ENCRYPTION_KEY is treated as key ID "default" and is fully supported.
    """

    _instance: Optional["CryptoEngine"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "CryptoEngine":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._engines: Dict[str, AESGCM] = {}
                    instance._active_key_id: str = "default"
                    instance._index_secret: Optional[bytes] = None
                    instance._init()
                    cls._instance = instance
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Clear the singleton instance to force re-initialization (useful for key rotation)."""
        cls._instance = None

    def _derive_aes_key(self, raw_key: str, key_id: str) -> bytes:
        """Derive a 256-bit AES key from a raw key string using Argon2id."""
        from argon2.low_level import hash_secret_raw, Type
        # Salt = KDF_SALT + tenant_id + key_id — unique per tenant and per key version
        kdf_salt_str = config.MASK_KDF_SALT + "-" + config.MASK_TENANT_ID + "-" + key_id
        kdf_salt_bytes = hashlib.sha256(kdf_salt_str.encode("utf-8")).digest()[:16]
        return hash_secret_raw(
            secret=raw_key.encode("utf-8"),
            salt=kdf_salt_bytes,
            time_cost=2,
            memory_cost=19456,  # 19 MiB
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )

    def _init(self) -> None:
        """Initialize the keyring and index secret.

        Keyring loading order:
          1. MASK_KEYRING (JSON): e.g. '{"v1": "oldkey", "v2": "newkey"}'
             The last key in the JSON object becomes the active key.
          2. MASK_ENCRYPTION_KEY (legacy): treated as key ID "default".
          3. Dev mode auto-generate if MASK_DEV_MODE=true.
        """
        try:
            from argon2.low_level import hash_secret_raw, Type
        except ImportError as exc:
            raise ImportError(
                "The 'argon2-cffi' package is required for Mask SDK cryptographic operations. "
                "Install with: pip install 'mask-privacy[crypto]' or pip install argon2-cffi"
            ) from exc

        from mask_privacy.core.key_provider import get_key_provider

        # ── Build the keyring ──────────────────────────────────────────────
        provider = get_key_provider()
        keyring_json = provider.get_keyring()
        raw_keys: Dict[str, str] = {}
        active_key_id = "default"

        if keyring_json:
            try:
                raw_keys = json.loads(keyring_json)
                if not isinstance(raw_keys, dict) or not raw_keys:
                    raise ValueError("MASK_KEYRING must be a non-empty JSON object.")
                # The last key in insertion order is the active key (Python 3.7+ dicts are ordered)
                active_key_id = list(raw_keys.keys())[-1]
                logger.info(
                    "Keyring loaded: %d key(s), active key ID=%s", len(raw_keys), active_key_id
                )
            except (json.JSONDecodeError, ValueError) as e:
                raise RuntimeError(f"Invalid MASK_KEYRING format: {e}") from e
        else:
            # Legacy single-key mode
            key = provider.get_encryption_key()
            if not key:
                if config.MASK_DEV_MODE:
                    key = secrets.token_hex(32)
                    os.environ["MASK_ENCRYPTION_KEY"] = key
                    logger.warning(
                        "MASK_DEV_MODE is enabled. Using a generated throwaway key. "
                        "DO NOT USE THIS IN PRODUCTION — tokens will be lost on restart."
                    )
                else:
                    from mask_privacy.core.exceptions import MaskSecurityError
                    raise MaskSecurityError(
                        "MASK_ENCRYPTION_KEY or MASK_KEYRING is not set. "
                        "Set one of these, or set MASK_DEV_MODE=true for ephemeral use."
                    )
            raw_keys = {"default": key}
            active_key_id = "default"

        # ── Derive AES keys for every entry in the keyring ─────────────────
        self._engines = {}
        for kid, raw_key in raw_keys.items():
            self._engines[kid] = AESGCM(self._derive_aes_key(raw_key, kid))
        self._active_key_id = active_key_id

        # ── Blind Index Secret (separate Argon2id derivation) ───────────────
        provider = get_key_provider()
        master_key = provider.get_master_key() or list(raw_keys.values())[-1]
        index_salt_str = config.MASK_BLIND_INDEX_SALT + "-" + config.MASK_TENANT_ID
        index_salt_bytes = hashlib.sha256(index_salt_str.encode("utf-8")).digest()[:16]
        self._index_secret = hash_secret_raw(
            secret=master_key.encode("utf-8"),
            salt=index_salt_bytes,
            time_cost=2,
            memory_cost=19456,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )

    def get_index_secret(self) -> bytes:
        """Return the secret used for HMAC-based blind indexing."""
        if self._index_secret is None:
            raise RuntimeError("CryptoEngine not initialized. No index secret available.")
        return self._index_secret

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the active keyring key.

        Envelope format: aes:v2:{keyId}:{base64(iv + authTag + ciphertext)}
        """
        aesgcm = self._engines.get(self._active_key_id)
        if aesgcm is None:
            raise RuntimeError(
                f"CryptoEngine: active key ID '{self._active_key_id}' not found in keyring."
            )

        iv = os.urandom(12)
        ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        # Wire format: iv (12) + authTag (16) + ciphertext
        tag = ciphertext_and_tag[-16:]
        encrypted_text = ciphertext_and_tag[:-16]
        combined = iv + tag + encrypted_text
        b64 = base64.b64encode(combined).decode("utf-8")
        return f"{AES_V2_PREFIX}{self._active_key_id}:{b64}"

    def _decrypt_aes_gcm_b64(self, key_id: str, b64_data: str) -> str:
        """Shared AES-GCM decryption. Routes to the correct historical key by ID."""
        aesgcm = self._engines.get(key_id)
        if aesgcm is None:
            from mask_privacy.core.exceptions import MaskDecryptionError
            raise MaskDecryptionError(
                f"No key found for key ID '{key_id}'. "
                "Ensure the key is present in MASK_KEYRING."
            )
        combined = base64.b64decode(b64_data)
        iv = combined[0:12]
        tag = combined[12:28]
        encrypted_text = combined[28:]
        python_format_ciphertext = encrypted_text + tag
        return aesgcm.decrypt(iv, python_format_ciphertext, None).decode("utf-8")

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
        """Decrypt ciphertext. Supports all historical envelope formats:

          1. aes:v2:{keyId}:{base64}  — current keyring format
          2. aes:v1:{base64}          — legacy single-key format (key ID = "default")
          3. aes:{base64}             — oldest legacy format (key ID = "default")
          4. Fernet                   — original Fernet-based format
        """
        if not self._engines:
            raise RuntimeError("CryptoEngine not initialized.")

        try:
            if ciphertext.startswith(AES_V2_PREFIX):
                # aes:v2:{keyId}:{base64}
                rest = ciphertext[len(AES_V2_PREFIX):]
                separator = rest.index(":")
                key_id = rest[:separator]
                b64_data = rest[separator + 1:]
                return self._decrypt_aes_gcm_b64(key_id, b64_data)

            if ciphertext.startswith(AES_GCM_PREFIX):
                # aes:v1:{base64} — implicit key ID "default"
                return self._decrypt_aes_gcm_b64("default", ciphertext[len(AES_GCM_PREFIX):])

            if ciphertext.startswith(AES_GCM_LEGACY_PREFIX):
                # aes:{base64} — oldest format, implicit key ID "default"
                return self._decrypt_aes_gcm_b64("default", ciphertext[len(AES_GCM_LEGACY_PREFIX):])

            # Attempt legacy Fernet decryption
            return self._decrypt_legacy_fernet(ciphertext)

        except Exception as e:
            from mask_privacy.core.exceptions import MaskDecryptionError
            logger.error(
                "Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY / MASK_KEYRING."
            )
            raise MaskDecryptionError("Decryption failed") from e


def get_crypto_engine() -> CryptoEngine:
    """Return the configured crypto engine singleton."""
    return CryptoEngine()
