"""
Vault abstraction layer for Mask Privacy SDK.

Provides pluggable backends for token-to-plaintext storage:
  - MemoryVault: In-process dict (dev/testing, single-process only)
  - RedisVault: Redis-backed (production, multi-pod K8s)
  - DynamoDBVault: AWS DynamoDB-backed (AWS-native enterprises)
  - MemcachedVault: Memcached-backed (lightweight distributed cache)

The active vault is selected via the MASK_VAULT_TYPE env var.
"""

import os
import time
import logging
import hashlib
import threading
from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple

from mask.core.fpe import generate_fpe_token
from mask.core.crypto import get_crypto_engine

logger = logging.getLogger("mask.vault")

# Abstract base

class BaseVault(ABC):
    """Interface every vault backend must implement."""

    @abstractmethod
    def store(self, token: str, plaintext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        """Persist a token → plaintext mapping with a TTL. Optionally save a reverse lookup hash."""

    @abstractmethod
    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        """Return the existing unexpired token for a given plaintext hash, or None."""

    @abstractmethod
    def retrieve(self, token: str) -> Optional[str]:
        """Return the plaintext for *token*, or None if missing/expired."""

def _hash_plaintext(plaintext: str) -> str:
    """Helper to deterministically hash plaintext for reverse lookups in distributed vaults."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# In-memory implementation (single-process, dev / testing)

class MemoryVault(BaseVault):
    """Dict-backed vault.  Fast, but state is lost across processes. Thread-safe."""

    def __init__(self) -> None:
        # _store maps token -> (ciphertext, expiry, pt_hash_or_none)
        self._store: dict[str, Tuple[str, float, Optional[str]]] = {}
        self._reverse_store: dict[str, str] = {}
        self._lock = threading.Lock()

    def _cleanup(self) -> None:
        # Caller must hold _lock
        now = time.time()
        expired = [k for k, (_, exp, _h) in self._store.items() if now > exp]
        for k in expired:
            _, _, pt_hash = self._store[k]
            del self._store[k]
            if pt_hash and self._reverse_store.get(pt_hash) == k:
                del self._reverse_store[pt_hash]

    def store(self, token: str, plaintext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        with self._lock:
            self._cleanup()
            self._store[token] = (plaintext, time.time() + ttl_seconds, pt_hash)
            if pt_hash:
                self._reverse_store[pt_hash] = token
            
    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        with self._lock:
            self._cleanup()
            token = self._reverse_store.get(pt_hash)
            if token and token in self._store:
                return token
        return None

    def retrieve(self, token: str) -> Optional[str]:
        with self._lock:
            self._cleanup()
            entry = self._store.get(token)
            if entry is None:
                return None
            plaintext, exp, pt_hash = entry
            if time.time() > exp:
                del self._store[token]
                if pt_hash and self._reverse_store.get(pt_hash) == token:
                    del self._reverse_store[pt_hash]
                return None
            return plaintext

    def delete(self, token: str) -> None:
        with self._lock:
            entry = self._store.pop(token, None)
            if entry:
                _, _, pt_hash = entry
                if pt_hash and self._reverse_store.get(pt_hash) == token:
                    del self._reverse_store[pt_hash]


# Redis implementation (multi-pod, production)

class RedisVault(BaseVault):
    """Redis-backed vault for horizontally scaled deployments.

    Requires the `redis` package and a reachable Redis instance.
    Configure via:
        MASK_REDIS_URL  (default: redis://localhost:6379/0)
    """

    def __init__(self, **redis_kwargs: Any) -> None:
        try:
            import redis  # type: ignore
        except ImportError:
            raise ImportError(
                "The 'redis' package is required for RedisVault. "
                "Install it with: pip install redis"
            )
        url = os.environ.get("MASK_REDIS_URL", "redis://localhost:6379/0")
        
        # Merge url configuration with explicitly passed kwargs (like mTLS ssl_certfile)
        kwargs = dict(decode_responses=True)
        kwargs.update(redis_kwargs)
        
        self._client = redis.Redis.from_url(url, **kwargs)
        # Verify connectivity at init time so bad config fails fast
        self._client.ping()
        logger.info("RedisVault connected to %s", url)

    def store(self, token: str, plaintext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        pipe = self._client.pipeline()
        pipe.setex(f"mask:{token}", ttl_seconds, plaintext)
        if pt_hash:
            pipe.setex(f"mask-rev:{pt_hash}", ttl_seconds, token)
            # Store the hash so delete() can clean up the reverse mapping
            pipe.setex(f"mask-hash:{token}", ttl_seconds, pt_hash)
        pipe.execute()

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        token = self._client.get(f"mask-rev:{pt_hash}")
        if token:
            # Verify the token hasn't expired independently
            if self._client.exists(f"mask:{token}"):
                return token
            else:
                self._client.delete(f"mask-rev:{pt_hash}")
        return None

    def retrieve(self, token: str) -> Optional[str]:
        return self._client.get(f"mask:{token}")

    def delete(self, token: str) -> None:
        pt_hash = self._client.get(f"mask-hash:{token}")
        pipe = self._client.pipeline()
        pipe.delete(f"mask:{token}")
        pipe.delete(f"mask-hash:{token}")
        if pt_hash:
            pipe.delete(f"mask-rev:{pt_hash}")
        pipe.execute()


# DynamoDB implementation (AWS-native enterprises)

class DynamoDBVault(BaseVault):
    """AWS DynamoDB-backed vault for AWS-native enterprise deployments.

    Requires the `boto3` package and valid AWS credentials.
    Configure via:
        MASK_DYNAMODB_TABLE  (default: mask-vault)
        MASK_DYNAMODB_REGION (default: us-east-1)
    """

    def __init__(self) -> None:
        try:
            import boto3  # type: ignore
        except ImportError:
            raise ImportError(
                "The 'boto3' package is required for DynamoDBVault. "
                "Install it with: pip install boto3"
            )
        region = os.environ.get("MASK_DYNAMODB_REGION", "us-east-1")
        self._table_name = os.environ.get("MASK_DYNAMODB_TABLE", "mask-vault")
        self._client = boto3.resource("dynamodb", region_name=region)
        self._table = self._client.Table(self._table_name)
        logger.info("DynamoDBVault connected to table %s in %s", self._table_name, region)

    def store(self, token: str, plaintext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        import time as _time
        item = {
            "token": f"mask:{token}",
            "plaintext": plaintext,
            "ttl": int(_time.time()) + ttl_seconds,
        }
        if pt_hash:
            item["ptr_hash"] = pt_hash
            self._table.put_item(Item={
                "token": f"mask-rev:{pt_hash}",
                "plaintext": token,
                "ttl": int(_time.time()) + ttl_seconds,
            })
        self._table.put_item(Item=item)
        
    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        import time as _time
        resp = self._table.get_item(Key={"token": f"mask-rev:{pt_hash}"})
        item = resp.get("Item")
        if not item:
            return None
        if int(_time.time()) > int(item.get("ttl", 0)):
            self._table.delete_item(Key={"token": f"mask-rev:{pt_hash}"})
            return None
            
        token = item.get("plaintext")
        # Verify the actual token still exists
        return token if self.retrieve(token) is not None else None

    def retrieve(self, token: str) -> Optional[str]:
        import time as _time
        resp = self._table.get_item(Key={"token": f"mask:{token}"})
        item = resp.get("Item")
        if item is None:
            return None
        if int(_time.time()) > int(item.get("ttl", 0)):
            # Use the stored ptr_hash (not the ciphertext) to clean reverse mapping
            pt_hash = item.get("ptr_hash")
            if pt_hash:
                self._table.delete_item(Key={"token": f"mask-rev:{pt_hash}"})
            self._table.delete_item(Key={"token": f"mask:{token}"})
            return None
        return item.get("plaintext")

    def delete(self, token: str) -> None:
        # Get the full item to extract the stored ptr_hash
        resp = self._table.get_item(Key={"token": f"mask:{token}"})
        item = resp.get("Item")
        if item:
            pt_hash = item.get("ptr_hash")
            if pt_hash:
                self._table.delete_item(Key={"token": f"mask-rev:{pt_hash}"})
        self._table.delete_item(Key={"token": f"mask:{token}"})


# Memcached implementation (lightweight distributed cache)

class MemcachedVault(BaseVault):
    """Memcached-backed vault as a lightweight alternative to Redis.

    Requires the `pymemcache` package and a reachable Memcached instance.
    Configure via:
        MASK_MEMCACHED_HOST (default: localhost)
        MASK_MEMCACHED_PORT (default: 11211)
    """

    def __init__(self, **memcache_kwargs: Any) -> None:
        try:
            from pymemcache.client.base import Client  # type: ignore
        except ImportError:
            raise ImportError(
                "The 'pymemcache' package is required for MemcachedVault. "
                "Install it with: pip install pymemcache"
            )
        host = os.environ.get("MASK_MEMCACHED_HOST", "localhost")
        port = int(os.environ.get("MASK_MEMCACHED_PORT", "11211"))
        
        # Support passing explicit tls_context kwargs for mTLS
        kwargs = dict(memcache_kwargs)
        if "tls_context" not in kwargs:
            # Check for generic `ssl_context` sometimes used and map it
            if "ssl_context" in kwargs:
                kwargs["tls_context"] = kwargs.pop("ssl_context")

        self._client = Client((host, port), **kwargs)
        logger.info("MemcachedVault connected to %s:%d", host, port)

    def store(self, token: str, plaintext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        self._client.set(f"mask:{token}", plaintext, expire=ttl_seconds)
        if pt_hash:
            self._client.set(f"mask-rev:{pt_hash}", token, expire=ttl_seconds)
            # Store the hash so delete() can clean up the reverse mapping
            self._client.set(f"mask-hash:{token}", pt_hash, expire=ttl_seconds)

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        val = self._client.get(f"mask-rev:{pt_hash}")
        if val is None:
            return None
        token = val.decode("utf-8") if isinstance(val, bytes) else val
        # Verify primary key exists
        return token if self.retrieve(token) is not None else None

    def retrieve(self, token: str) -> Optional[str]:
        val = self._client.get(f"mask:{token}")
        if val is None:
            return None
        return val.decode("utf-8") if isinstance(val, bytes) else val

    def delete(self, token: str) -> None:
        # Look up the stored pt_hash (not the ciphertext)
        hash_val = self._client.get(f"mask-hash:{token}")
        pt_hash = hash_val.decode("utf-8") if isinstance(hash_val, bytes) else hash_val
        self._client.delete(f"mask:{token}")
        self._client.delete(f"mask-hash:{token}")
        if pt_hash:
            self._client.delete(f"mask-rev:{pt_hash}")


# Singleton accessor

_vault_instance: Optional[BaseVault] = None

DEFAULT_TTL = int(os.environ.get("MASK_VAULT_TTL", "600"))  # 10 min


def get_vault() -> BaseVault:
    """Return the configured vault singleton (lazy-init)."""
    global _vault_instance
    if _vault_instance is None:
        vault_type = os.environ.get("MASK_VAULT_TYPE", "memory").lower()
        if vault_type == "redis":
            _vault_instance = RedisVault()
        elif vault_type == "memory":
            _vault_instance = MemoryVault()
        elif vault_type == "dynamodb":
            _vault_instance = DynamoDBVault()
        elif vault_type == "memcached":
            _vault_instance = MemcachedVault()
        else:
            raise ValueError(
                f"Unknown MASK_VAULT_TYPE='{vault_type}'. "
                "Supported values: 'memory', 'redis', 'dynamodb', 'memcached'."
            )
        logger.info("Vault initialised: %s", type(_vault_instance).__name__)
    return _vault_instance


def reset_vault() -> None:
    """Reset the vault singleton.  Useful in tests."""
    global _vault_instance
    _vault_instance = None


# Public convenience API  (encode / decode)

def encode(raw_text: str, *, ttl: Optional[int] = None) -> str:
    """Tokenise *raw_text*, encrypt it, store in vault, return the FPE token.
    If *raw_text* has already been tokenised and is active, returns the existing token.
    """
    vault = get_vault()
    pt_hash = _hash_plaintext(raw_text)
    
    # 1. Deduplication check
    existing_token = vault.get_token_by_plaintext_hash(pt_hash)
    if existing_token:
        # Check if it actually exists in the primary store and hasn't expired.
        # The backend should handle this, but just to be safe.
        if vault.retrieve(existing_token) is not None:
            logger.debug("encode  %s → %s (cached)", repr(raw_text)[:20], existing_token)
            return existing_token
    
    # 2. Generate new token
    token = generate_fpe_token(raw_text)
    
    # 3. Encrypt the plaintext before it touches the vault
    crypto = get_crypto_engine()
    ciphertext = crypto.encrypt(raw_text)
    
    # 4. Store with reverse lookup hash
    vault.store(token, ciphertext, ttl or DEFAULT_TTL, pt_hash=pt_hash)
    
    logger.debug("encode  %s → %s (new)", repr(raw_text)[:20], token)
    return token


class DecodeError(Exception):
    """Raised when strict detokenisation fails for a token."""


def decode(token: str) -> str:
    """Detokenise *token* via O(1) vault lookup and decrypt it.

    This strict helper either returns plaintext or raises ``DecodeError``:

    - If the token is missing or expired, a ``DecodeError`` is raised.
    - If decryption fails, a ``DecodeError`` is raised.
    """
    ciphertext = get_vault().retrieve(token)
    if ciphertext is None:
        logger.warning("Token not found or expired: %s", token)
        raise DecodeError("Token not found or expired")

    try:
        crypto = get_crypto_engine()
        plaintext = crypto.decrypt(ciphertext)
    except Exception as exc:
        logger.error("Failed to decrypt token %s payload.", token)
        raise DecodeError("Failed to decrypt token payload") from exc

    logger.debug("decode  %s → %s", token, repr(plaintext)[:20])
    return plaintext


def _decode_lenient(token: str) -> str:
    """Internal helper used by integrations that prefer lenient semantics.

    Returns plaintext when strict ``decode`` succeeds, otherwise falls back
    to returning the original *token* string. This preserves legacy behaviour
    for callers that explicitly opt in to resilience over strictness.
    """
    try:
        return decode(token)
    except DecodeError:
        return token
