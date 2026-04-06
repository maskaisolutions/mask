"""
Custom exception hierarchy for the Mask SDK.

Provides specific exceptions so callers can implement targeted
retry/fallback logic instead of catching generic ``Exception``.
"""


class MaskError(Exception):
    """Base exception for all Mask SDK errors."""


class MaskVaultConnectionError(MaskError):
    """Raised when a vault backend (Redis, DynamoDB) is unreachable."""


class MaskDecryptionError(MaskError):
    """Raised when CryptoEngine.decrypt() fails (bad key, corrupt data)."""


class MaskNLPTimeout(MaskError):
    """Raised when spaCy / Presidio analysis exceeds the time budget."""


class MaskSecurityError(MaskError):
    """Raised when mandatory security keys (MASK_MASTER_KEY, etc.) are missing."""


class TokenCollisionError(MaskError):
    """Raised when a newly generated token already maps to a *different* plaintext.

    This indicates a Birthday-Paradox collision in the deterministic pseudonymization
    engine — two distinct plaintexts produced the same token.  The vault refuses to
    overwrite existing PII, so the caller must handle the collision (e.g. by adding
    a per-tenant salt or increasing token entropy).

    Attributes:
        token: The colliding token string.
        existing_hash: HMAC-blind-index hash of the plaintext already stored under this token.
        incoming_hash: HMAC-blind-index hash of the new plaintext that triggered the collision.
    """

    def __init__(self, token: str, existing_hash: str, incoming_hash: str) -> None:
        self.token = token
        self.existing_hash = existing_hash
        self.incoming_hash = incoming_hash
        super().__init__(
            f"Token collision detected for token '{token}'. "
            f"Existing plaintext hash '{existing_hash[:8]}…' conflicts with "
            f"incoming hash '{incoming_hash[:8]}…'. "
            "Increase token entropy or adjust tenant salt configuration."
        )

