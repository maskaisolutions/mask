"""
Explicit Client initialization for the Mask SDK.

Provides ``MaskClient`` — a unified, explicitly-configured client that
bundles vault, crypto, scanner, and audit logger into a single object.
"""

from typing import Optional, Dict, Any

from mask.core.vault import get_vault, BaseVault, _hash_plaintext
from mask.core.crypto import get_crypto_engine, CryptoEngine
from mask.core.scanner import get_scanner, PresidioScanner
from mask.core.fpe import generate_fpe_token
from mask.telemetry.audit_logger import get_audit_logger, AuditLogger


class MaskClient:
    """Explicitly configured Mask SDK client.

    Using this client avoids global singleton state conflicts, making it
    suitable for multi-tenant applications or environments with complex
    VPC boundaries.

    Usage::

        from mask import MaskClient
        client = MaskClient(ttl=300)
        token = client.encode("user@example.com")
        plaintext = client.decode(token)
        safe_text = client.scan_and_tokenize("Call me at 555-123-4567")
    """

    def __init__(
        self,
        vault: Optional[BaseVault] = None,
        crypto: Optional[CryptoEngine] = None,
        scanner: Optional[PresidioScanner] = None,
        audit_logger: Optional[AuditLogger] = None,
        ttl: int = 600,
    ) -> None:
        """Initialise the client with specific component instances.

        If an instance is not provided, the client will fall back to
        the standard environment-configured singleton for that component.
        """
        self.vault = vault or get_vault()
        self.crypto = crypto or get_crypto_engine()
        self.scanner = scanner or get_scanner()
        self.logger = audit_logger or get_audit_logger()
        self.ttl = ttl

        # Ensure the audit logger is running
        self.logger.start()

    def encode(self, raw_text: str) -> str:
        """Tokenise *raw_text*, encrypt it, and store it in the vault.

        Includes deduplication: if the same plaintext has been encoded
        before and the token is still active, the existing token is returned.
        """
        pt_hash = _hash_plaintext(raw_text)

        # 1. Deduplication check
        existing_token = self.vault.get_token_by_plaintext_hash(pt_hash)
        if existing_token and self.vault.retrieve(existing_token) is not None:
            self.logger.log("encode", existing_token, "opaque")
            return existing_token

        # 2. Generate deterministic token
        token = generate_fpe_token(raw_text)

        # 3. Encrypt
        ciphertext = self.crypto.encrypt(raw_text)

        # 4. Store with reverse lookup hash
        self.vault.store(token, ciphertext, self.ttl, pt_hash=pt_hash)

        self.logger.log("encode", token, "opaque")
        return token

    def decode(self, token: str) -> str:
        """Retrieve token from vault and decrypt it."""
        ciphertext = self.vault.retrieve(token)
        if ciphertext is None:
            self.logger.log("expired", token, "opaque")
            return token

        try:
            plaintext = self.crypto.decrypt(ciphertext)
            self.logger.log("decode", token, "opaque")
            return plaintext
        except Exception:
            self.logger.log("error", token, "opaque", error="decryption_failed")
            return token

    def scan_and_tokenize(self, text: str) -> str:
        """Scan text using the Waterfall pipeline and replace PII with FPE tokens."""
        return self.scanner.scan_and_tokenize(text, encode_fn=self.encode)
