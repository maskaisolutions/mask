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

