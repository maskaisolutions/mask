"""
Explicit Client initialization for the Mask SDK.

Provides ``MaskClient`` — a unified, explicitly-configured client that
bundles vault, crypto, scanner, and audit logger into a single object.
"""

import logging
from typing import Any, Optional

from mask_privacy.core.vault import get_vault, BaseVault, _hash_plaintext, detokenize_text
from mask_privacy.core.crypto import get_crypto_engine, CryptoEngine
from mask_privacy.core.scanner import get_scanner, PresidioScanner
from mask_privacy.core.fpe import generate_fpe_token, looks_like_token
from mask_privacy.telemetry.audit_logger import get_audit_logger, AuditLogger

logger = logging.getLogger("mask.client")


class MaskClient:
    """Explicitly configured Mask SDK client.

    Using this client avoids global singleton state conflicts, making it
    suitable for multi-tenant applications or environments with complex
    VPC boundaries.

    Usage::

        from mask_privacy import MaskClient
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
        async_vault: Optional[Any] = None,
    ) -> None:
        """Initialise the client with specific component instances.

        If an instance is not provided, the client will fall back to
        the standard environment-configured singleton for that component.
        """
        self.vault = vault or get_vault()
        self.crypto = crypto or get_crypto_engine()
        self.scanner = scanner or get_scanner()
        self.audit_logger = audit_logger or get_audit_logger()
        self.logger = self.audit_logger  # backward compat alias
        self.ttl = ttl
        
        if async_vault is not None:
            self.async_vault = async_vault
        else:
            from mask_privacy.core.vault import get_async_vault
            self.async_vault = get_async_vault() if vault is None else None

        # Ensure the audit logger is running
        self.audit_logger.start()

    def encode(self, raw_text: str) -> str:
        """Tokenise *raw_text*, encrypt it, and store it in the vault.

        Includes deduplication: if the same plaintext has been encoded
        before and the token is still active, the existing token is returned.
        """
        # Token Guard: never re-encode a value that is already a Mask token
        if looks_like_token(raw_text):
            return raw_text

        # Normalise whitespace so " Alice " and "Alice" share the same hash
        raw_text = raw_text.strip()

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
        except Exception as e:
            self.logger.log("error", token, "opaque", error="decryption_failed")
            import os
            if os.environ.get("MASK_DEV_MODE") == "true":
                return token
            from mask_privacy.core.vault import DecodeError
            raise DecodeError(f"Decryption failed for token {token}: {e}")

    def scan_and_tokenize(self, text: str) -> str:
        """Scan text using the Waterfall pipeline and replace PII with FPE tokens."""
        return self.scanner.scan_and_tokenize(text, encode_fn=self.encode)

    async def aencode(self, raw_text: str) -> str:
        """Native async wrapper for ``encode()``."""
        if looks_like_token(raw_text):
            return raw_text

        if not getattr(self, "async_vault", None):
            import asyncio
            return await asyncio.to_thread(self.encode, raw_text)

        raw_text = raw_text.strip()
        index_secret = self.crypto.get_index_secret()
        pt_hash = _hash_plaintext(raw_text, index_secret)

        existing_token = await self.async_vault.get_token_by_plaintext_hash(pt_hash)
        if existing_token and await self.async_vault.retrieve(existing_token) is not None:
            await self.audit_logger.alog("encode", existing_token, "opaque")
            return existing_token

        token = generate_fpe_token(raw_text)
        ciphertext = self.crypto.encrypt(raw_text)
        await self.async_vault.store(token, ciphertext, self.ttl, pt_hash=pt_hash)
        await self.audit_logger.alog("encode", token, "opaque")
        return token

    async def adecode(self, token: str) -> str:
        """Native async wrapper for ``decode()``."""
        if not getattr(self, "async_vault", None):
            import asyncio
            return await asyncio.to_thread(self.decode, token)

        ciphertext = await self.async_vault.retrieve(token)
        if ciphertext is None:
            await self.audit_logger.alog("expired", token, "opaque")
            return token

        try:
            plaintext = self.crypto.decrypt(ciphertext)
            await self.audit_logger.alog("decode", token, "opaque")
            return plaintext
        except Exception as e:
            await self.audit_logger.alog("error", token, "opaque", error="decryption_failed")
            import os
            if os.environ.get("MASK_DEV_MODE") == "true":
                return token
            from mask_privacy.core.vault import DecodeError
            raise DecodeError(f"Decryption failed for token {token}: {e}")

    async def ascan_and_tokenize(self, text: str) -> str:
        """Native async version of ``scan_and_tokenize()``.
        
        Uses the native async scanning pipeline for non-blocking operation.
        """
        return await self.scanner.ascan_and_tokenize(text, encode_fn=self.aencode)

    def detokenize_text(self, text: str) -> str:
        """Find and replace all tokens within *text* with their plaintext."""
        if not text or not isinstance(text, str):
            return text
        import re
        from mask_privacy.core.fpe import TOKEN_PATTERN
        
        def replace_match(match):
            try:
                # Use self.decode to ensure the explicit vault/crypto is used
                return self.decode(match.group(0))
            except:
                return match.group(0)

        return re.sub(TOKEN_PATTERN, replace_match, text)

    async def adetokenize_text(self, text: str) -> str:
        """Async wrapper for ``detokenize_text()``."""
        import asyncio
        if not getattr(self, "async_vault", None):
            return await asyncio.to_thread(self.detokenize_text, text)
            
        import re
        from mask_privacy.core.fpe import TOKEN_PATTERN
        
        if not text or not isinstance(text, str):
            return text

        tokens = re.findall(TOKEN_PATTERN, text)
        if not tokens:
            return text

        async def _decode_one(tok: str) -> tuple:
            try:
                plaintext = await self.adecode(tok)
                return (tok, plaintext)
            except:
                return (tok, tok)

        results = await asyncio.gather(*[_decode_one(t) for t in set(tokens)])
        
        result = text
        for tok, plaintext in results:
            if plaintext != tok:
                result = result.replace(tok, plaintext)
        
        return result

    def close(self) -> None:
        """Gracefully shut down all SDK resources (vault connections, audit logger)."""
        try:
            self.audit_logger.stop()
        except Exception:
            pass
        logger.info("MaskClient closed.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
