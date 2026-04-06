"""
Vault abstraction layer for Mask Privacy SDK.
"""

import time
import json
import hmac
import hashlib
import logging
import threading
from typing import Dict, Any, Optional, List

from mask_privacy.core.fpe import looks_like_token, generate_dp_token
from mask_privacy.core.crypto import get_crypto_engine
from mask_privacy.core.exceptions import MaskVaultConnectionError, TokenCollisionError
from mask_privacy.telemetry.audit_logger import get_audit_logger
from mask_privacy.core.search import BucketManager
from mask_privacy import config

class DecodeError(Exception):
    """Raised when a token cannot be decoded/decrypted."""
    pass

logger = logging.getLogger("mask.vault")

_STRATEGY_WARNED = False

def _get_fail_strategy() -> str:
    global _STRATEGY_WARNED
    if config.MASK_FAIL_STRATEGY:
        return config.MASK_FAIL_STRATEGY
        
    # Secure-by-default: fail-shut unless explicitly in dev mode
    if config.MASK_ENV in ["dev", "development"]:
        if not _STRATEGY_WARNED:
            logger.warning("MASK_ENV is 'dev'; defaulting to 'open'. PII may leak during vault failures.")
            _STRATEGY_WARNED = True
        return "open"
    
    # Default to closed for production/unset envs
    return "closed"

def _hash_plaintext(plaintext: str, secret: Optional[bytes] = None) -> str:
    """Deterministically hash plaintext for reverse lookups.
    
    Uses HMAC-SHA256 with an enterprise-configurable salt to prevent leakage.
    """
    trimmed = plaintext.strip()
    if secret is None:
        from mask_privacy.core.crypto import get_crypto_engine
        secret = get_crypto_engine().get_index_secret()
        
    return hmac.new(secret, trimmed.encode("utf-8"), hashlib.sha256).hexdigest()


class BaseVault:
    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None, metadata: Optional[Dict[str, str]] = None) -> None:
        """Store a token → ciphertext mapping.

        Args:
            token: The deterministic pseudonymization token.
            ciphertext: AES-GCM encrypted plaintext.
            ttl_seconds: Time-to-live in seconds.
            pt_hash: HMAC blind-index of the plaintext for reverse lookups.
            metadata: Optional compliance context (e.g. purpose, policy_id, agent_id).
                      Stored alongside the ciphertext for SOC 2 Purpose Limitation audits.
        """
        raise NotImplementedError

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        raise NotImplementedError

    def retrieve(self, token: str) -> Optional[str]:
        raise NotImplementedError

    def get_pt_hash_for_token(self, token: str) -> Optional[str]:
        """Return the plaintext hash stored for a given token, or None.
        
        Used by conflict detection in encode() to verify ownership of a token
        before raising TokenCollisionError.
        """
        raise NotImplementedError

    def delete(self, token: str) -> None:
        raise NotImplementedError


class MemoryVault(BaseVault):
    """In-memory implementation (dev / testing)."""

    def __init__(self):
        # Maps token -> {"ciphertext": val, "expiry": ts, "pt_hashes": set(hashes)}
        self._store: Dict[str, Dict[str, Any]] = {}
        # Maps hash -> token
        self._reverse_store: Dict[str, str] = {}
        self._lock = threading.RLock()

    def _cleanup(self) -> None:
        import random
        # Probabilistic cleanup to prevent memory bloat
        # Configurable frequency (default 1%) balances CPU vs Memory usage
        cleanup_freq = config.MASK_VAULT_CLEANUP_FREQUENCY
        if random.random() > cleanup_freq:
            return
            
        now = time.time()
        with self._lock:
            # Create a list to avoid "dictionary changed size during iteration"
            to_delete = [t for t, e in self._store.items() if now > e["expiry"]]
            for token in to_delete:
                entry = self._store.pop(token, None)
                if entry:
                    hashes = entry.get("pt_hashes", [])
                    for h in hashes:
                        if self._reverse_store.get(h) == token:
                            self._reverse_store.pop(h, None)

    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None, metadata: Optional[Dict[str, str]] = None) -> None:
        self._cleanup()
        with self._lock:
            if token not in self._store:
                self._store[token] = {
                    "ciphertext": ciphertext,
                    "expiry": time.time() + ttl_seconds,
                    "pt_hashes": set(),
                    "metadata": metadata or {},
                }
            
            entry = self._store[token]
            entry["ciphertext"] = ciphertext  # update if already exists
            entry["expiry"] = time.time() + ttl_seconds
            if metadata:
                entry["metadata"].update(metadata)
            
            if pt_hash:
                entry["pt_hashes"].add(pt_hash)
                self._reverse_store[pt_hash] = token

    def get_pt_hash_for_token(self, token: str) -> Optional[str]:
        with self._lock:
            entry = self._store.get(token)
            if not entry:
                return None
            hashes = entry.get("pt_hashes", set())
            return next(iter(hashes), None) if hashes else None

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        self._cleanup()
        with self._lock:
            return self._reverse_store.get(pt_hash)

    def retrieve(self, token: str) -> Optional[str]:
        self._cleanup()
        with self._lock:
            entry = self._store.get(token)
            if not entry:
                return None
            if time.time() > entry["expiry"]:
                self.delete(token)
                return None
            return entry["ciphertext"]

    def delete(self, token: str) -> None:
        with self._lock:
            entry = self._store.pop(token, None)
            if entry:
                hashes = entry.get("pt_hashes", [])
                for h in hashes:
                    if self._reverse_store.get(h) == token:
                        self._reverse_store.pop(h, None)


class RedisVault(BaseVault):
    """Redis-backed vault for horizontally scaled deployments."""

    def __init__(self, **options: Any):
        try:
            import redis
            url = config.MASK_REDIS_URL
            self._client = redis.from_url(url, decode_responses=True, **options)
            self._client.ping()
            logger.info("RedisVault connected to %s", url)
        except Exception as e:
            raise MaskVaultConnectionError(f"Failed to connect to Redis: {e}")

    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None, metadata: Optional[Dict[str, str]] = None) -> None:
        try:
            pipe = self._client.pipeline()
            # Serialize metadata alongside ciphertext as a JSON envelope
            payload = ciphertext
            if metadata:
                payload = json.dumps({"ct": ciphertext, "meta": metadata})
            pipe.setex(f"mask:{token}", ttl_seconds, payload)
            if pt_hash:
                pipe.setex(f"mask-rev:{pt_hash}", ttl_seconds, token)
                pipe.setex(f"mask-hash:{token}", ttl_seconds, pt_hash)
            pipe.execute()
        except Exception as e:
            raise MaskVaultConnectionError(f"Redis write failed: {e}")

    def get_pt_hash_for_token(self, token: str) -> Optional[str]:
        try:
            return self._client.get(f"mask-hash:{token}")
        except:
            return None

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        try:
            token = self._client.get(f"mask-rev:{pt_hash}")
            if not token:
                return None
            # Check if token still exists in primary store
            actual = self.retrieve(token)
            return token if actual else None
        except:
            return None

    def retrieve(self, token: str) -> Optional[str]:
        try:
            return self._client.get(f"mask:{token}")
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Redis read failed: {e}")
            return None

    def delete(self, token: str) -> None:
        try:
            pt_hash = self._client.get(f"mask-hash:{token}")
            pipe = self._client.pipeline()
            pipe.delete(f"mask:{token}")
            pipe.delete(f"mask-hash:{token}")
            if pt_hash:
                pipe.delete(f"mask-rev:{pt_hash}")
            pipe.execute()
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Redis delete failed: {e}")
            logger.warning("Redis delete failed: %s", e)


class AsyncRedisVault:
    """Async Redis vault using native ``redis.asyncio`` for zero-thread-pool I/O.

    Used internally by ``aencode`` / ``adecode`` for high-throughput async workloads.
    Falls back to wrapping ``RedisVault`` in ``asyncio.to_thread`` if ``redis.asyncio``
    is not available.
    """

    def __init__(self, **options: Any):
        try:
            import redis.asyncio as aioredis
            url = config.MASK_REDIS_URL
            self._client = aioredis.from_url(url, decode_responses=True, **options)
            logger.info("AsyncRedisVault connected to %s", url)
        except Exception as e:
            raise MaskVaultConnectionError(f"Failed to connect to async Redis: {e}")

    async def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None, metadata: Optional[Dict[str, str]] = None) -> None:
        try:
            pipe = self._client.pipeline()
            payload = ciphertext
            if metadata:
                payload = json.dumps({"ct": ciphertext, "meta": metadata})
            pipe.setex(f"mask:{token}", ttl_seconds, payload)
            if pt_hash:
                pipe.setex(f"mask-rev:{pt_hash}", ttl_seconds, token)
                pipe.setex(f"mask-hash:{token}", ttl_seconds, pt_hash)
            await pipe.execute()
        except Exception as e:
            raise MaskVaultConnectionError(f"Async Redis write failed: {e}")

    async def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        try:
            token = await self._client.get(f"mask-rev:{pt_hash}")
            if not token:
                return None
            actual = await self.retrieve(token)
            return token if actual else None
        except:
            return None

    async def retrieve(self, token: str) -> Optional[str]:
        try:
            return await self._client.get(f"mask:{token}")
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Async Redis read failed: {e}")
            return None

    async def delete(self, token: str) -> None:
        try:
            pt_hash = await self._client.get(f"mask-hash:{token}")
            pipe = self._client.pipeline()
            pipe.delete(f"mask:{token}")
            pipe.delete(f"mask-hash:{token}")
            if pt_hash:
                pipe.delete(f"mask-rev:{pt_hash}")
            await pipe.execute()
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Async Redis delete failed: {e}")
            logger.warning("Async Redis delete failed: %s", e)


class DynamoDBVault(BaseVault):
    """AWS DynamoDB-backed vault."""

    def __init__(self):
        try:
            import boto3
            self._region = config.MASK_DYNAMODB_REGION
            self._table_name = config.MASK_DYNAMODB_TABLE
            self._dynamodb = boto3.resource("dynamodb", region_name=self._region)
            self._table = self._dynamodb.Table(self._table_name)
            self._client = self._dynamodb.meta.client
            logger.info("DynamoDBVault connected to table %s in %s", self._table_name, self._region)
        except Exception as e:
            raise MaskVaultConnectionError(f"Failed to connect to DynamoDB: {e}")

    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        now = int(time.time())
        ttl_val = now + ttl_seconds
        
        if pt_hash:
            try:
                self._client.transact_write_items(
                    TransactItems=[
                        {
                            "Put": {
                                "TableName": self._table_name,
                                "Item": {
                                    "token": {"S": f"mask:{token}"},
                                    "ciphertext": {"S": ciphertext},
                                    "ttl": {"N": str(ttl_val)},
                                    "ptr_hash": {"S": pt_hash}
                                }
                            }
                        },
                        {
                            "Put": {
                                "TableName": self._table_name,
                                "Item": {
                                    "token": {"S": f"mask-rev:{pt_hash}"},
                                    "ciphertext": {"S": token},
                                    "ttl": {"N": str(ttl_val)}
                                }
                            }
                        }
                    ]
                )
            except Exception as e:
                logger.error("DynamoDB transact_write_items failed: %s", e)
                raise MaskVaultConnectionError(f"DynamoDB atomic write failed: {e}")
        else:
            try:
                self._table.put_item(
                    Item={
                        "token": f"mask:{token}",
                        "ciphertext": ciphertext,
                        "ttl": ttl_val
                    }
                )
            except Exception as e:
                raise MaskVaultConnectionError(f"DynamoDB write failed: {e}")

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        try:
            resp = self._table.get_item(Key={"token": f"mask-rev:{pt_hash}"})
            item = resp.get("Item")
            if not item:
                return None
            
            now = time.time()
            if now > item.get("ttl", 0):
                self._table.delete_item(Key={"token": f"mask-rev:{pt_hash}"})
                return None
            
            token = item.get("ciphertext")
            # Verify primary entry still exists
            return token if self.retrieve(token) else None
        except:
            return None

    def retrieve(self, token: str) -> Optional[str]:
        try:
            resp = self._table.get_item(Key={"token": f"mask:{token}"})
            item = resp.get("Item")
            if not item:
                return None
            
            now = time.time()
            if now > item.get("ttl", 0):
                pt_hash = item.get("ptr_hash")
                if pt_hash:
                    self._table.delete_item(Key={"token": f"mask-rev:{pt_hash}"})
                self._table.delete_item(Key={"token": f"mask:{token}"})
                return None
            
            return item.get("ciphertext")
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"DynamoDB read failed: {e}")
            return None

    def delete(self, token: str) -> None:
        try:
            resp = self._table.get_item(Key={"token": f"mask:{token}"})
            item = resp.get("Item")
            if item and item.get("ptr_hash"):
                self._table.delete_item(Key={"token": f"mask-rev:{item['ptr_hash']}"})
            self._table.delete_item(Key={"token": f"mask:{token}"})
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"DynamoDB delete failed: {e}")
            logger.warning("DynamoDB delete failed: %s", e)


class MemcachedVault(BaseVault):
    """Memcached-backed vault."""

    def __init__(self, **options: Any):
        try:
            from pymemcache.client.base import Client
            host = config.MASK_MEMCACHED_HOST
            port = config.MASK_MEMCACHED_PORT
            self._client = Client((host, port), **options)
            logger.info("MemcachedVault connected to %s:%s", host, port)
        except Exception as e:
            raise MaskVaultConnectionError(f"Failed to connect to Memcached: {e}")

    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        try:
            data = {f"mask:{token}": ciphertext}
            if pt_hash:
                data[f"mask-rev:{pt_hash}"] = token
                data[f"mask-hash:{token}"] = pt_hash
            self._client.set_multi(data, expire=ttl_seconds)
        except Exception as e:
            raise MaskVaultConnectionError(f"Memcached write failed: {e}")

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        try:
            val = self._client.get(f"mask-rev:{pt_hash}")
            if not val:
                return None
            token = val.decode("utf-8") if isinstance(val, bytes) else str(val)
            return token if self.retrieve(token) else None
        except:
            return None

    def retrieve(self, token: str) -> Optional[str]:
        try:
            val = self._client.get(f"mask:{token}")
            if not val:
                return None
            return val.decode("utf-8") if isinstance(val, bytes) else str(val)
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Memcached read failed: {e}")
            return None

    def delete(self, token: str) -> None:
        try:
            pt_hash = self._client.get(f"mask-hash:{token}")
            keys = [f"mask:{token}", f"mask-hash:{token}"]
            if pt_hash:
                h = pt_hash.decode("utf-8") if isinstance(pt_hash, bytes) else str(pt_hash)
                keys.append(f"mask-rev:{h}")
            self._client.delete_multi(keys)
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Memcached delete failed: {e}")
            logger.warning("Memcached delete failed: %s", e)


# Singleton accessor

_vault_lock = threading.Lock()
_vault_instance: Optional[BaseVault] = None
DEFAULT_TTL = config.MASK_VAULT_TTL

def get_vault() -> BaseVault:
    """Return the active vault singleton (lazy-init, thread-safe)."""
    global _vault_instance
    if _vault_instance is None:
        with _vault_lock:
            if _vault_instance is None:
                vault_type = config.MASK_VAULT_TYPE
        if vault_type == "redis":
            _vault_instance = RedisVault()
        elif vault_type == "dynamodb":
            _vault_instance = DynamoDBVault()
        elif vault_type == "memcached":
            _vault_instance = MemcachedVault()
        else:
            _vault_instance = MemoryVault()
        logger.info("Vault initialized: %s", _vault_instance.__class__.__name__)
    return _vault_instance

def reset_vault() -> None:
    global _vault_instance
    _vault_instance = None


# Public API

def encode(text: str, ttl: Optional[int] = None, search_buckets: Optional[List[str]] = None, search_bucket_size: int = 10, entity_type: str = "UNKNOWN", metadata: Optional[Dict[str, str]] = None) -> str:
    if looks_like_token(text):
        return text

    vault = get_vault()
    crypto = get_crypto_engine()
    index_secret = crypto.get_index_secret()
    pt_hash = _hash_plaintext(text, index_secret)

    # 1. Deduplication check
    existing = vault.get_token_by_plaintext_hash(pt_hash)
    if existing and vault.retrieve(existing):
        get_audit_logger().log("dedup", existing)
        return existing

    # 2. Generate new token
    token = generate_dp_token(text, entity_type=entity_type)
    ciphertext = crypto.encrypt(text)
    effective_ttl = ttl or DEFAULT_TTL

    # 3. Collision Detection — refuse to overwrite a different plaintext under the same token
    existing_ciphertext = vault.retrieve(token)
    if existing_ciphertext is not None:
        existing_hash = vault.get_pt_hash_for_token(token)
        if existing_hash and existing_hash != pt_hash:
            raise TokenCollisionError(
                token=token,
                existing_hash=existing_hash,
                incoming_hash=pt_hash,
            )
        # Same plaintext re-encoded (hash matches) — safe to proceed/update

    # 4. Store primary record with compliance metadata
    vault.store(token, ciphertext, effective_ttl, pt_hash, metadata=metadata)

    # 5. Search buckets
    if search_buckets:
        for b_type in search_buckets:
            if b_type == "numeric":
                b_val = BucketManager.numeric_bucket(text, search_bucket_size)
            else:
                b_val = BucketManager.date_bucket(text, b_type)
            b_hash = BucketManager.get_bucket_index(b_val)
            vault.store(token, ciphertext, effective_ttl, b_hash)

    get_audit_logger().log("encode", token)
    return token

def decode(token: str) -> str:
    vault = get_vault()
    ciphertext = vault.retrieve(token)
    if ciphertext is None:
        raise DecodeError("Token expired or missing")

    try:
        crypto = get_crypto_engine()
        plaintext = crypto.decrypt(ciphertext)
        get_audit_logger().log("decode", token)
        return plaintext
    except Exception as e:
        logger.error("Failed to decrypt token %s: %s", token, e)
        raise DecodeError(f"Decryption failed for token {token}: {e}")

def _decode_lenient(token: str) -> str:
    """Attempt to decode a token; return the token itself on failure (no raise)."""
    try:
        return decode(token)
    except:
        return token

_async_vault_instance: Any = None

def get_async_vault() -> Any:
    global _async_vault_instance
    if _async_vault_instance is None:
        vault_type = config.MASK_VAULT_TYPE
        if vault_type == "redis":
            _async_vault_instance = AsyncRedisVault()
        else:
            _async_vault_instance = False
    return _async_vault_instance if _async_vault_instance is not False else None


async def adecode(token: str) -> str:
    """Native async decode — uses AsyncRedisVault when vault type is 'redis', otherwise falls back to to_thread."""
    async_vault = get_async_vault()
    if not async_vault:
        import asyncio
        from functools import partial
        return await asyncio.to_thread(partial(decode, token))

    ciphertext = await async_vault.retrieve(token)
    if ciphertext is None:
        raise DecodeError("Token expired or missing")

    try:
        from mask_privacy.core.crypto import get_crypto_engine
        from mask_privacy.telemetry.audit_logger import get_audit_logger
        crypto = get_crypto_engine()
        plaintext = crypto.decrypt(ciphertext)
        get_audit_logger().log("decode", token)
        return plaintext
    except Exception as e:
        logger.error("Failed to decrypt token %s: %s", token, e)
        raise DecodeError(f"Decryption failed for token {token}: {e}")

async def aencode(text: str, ttl: Optional[int] = None, search_buckets: Optional[List[str]] = None, search_bucket_size: int = 10, entity_type: str = "UNKNOWN", metadata: Optional[Dict[str, str]] = None) -> str:
    """Native async encode — uses AsyncRedisVault when vault type is 'redis', otherwise falls back to to_thread."""
    if looks_like_token(text):
        return text

    async_vault = get_async_vault()
    if not async_vault:
        import asyncio
        from functools import partial
        return await asyncio.to_thread(partial(encode, text, ttl=ttl, search_buckets=search_buckets, search_bucket_size=search_bucket_size, entity_type=entity_type, metadata=metadata))

    crypto = get_crypto_engine()
    index_secret = crypto.get_index_secret()
    pt_hash = _hash_plaintext(text, index_secret)

    existing = await async_vault.get_token_by_plaintext_hash(pt_hash)
    if existing and await async_vault.retrieve(existing):
        get_audit_logger().log("dedup", existing)
        return existing

    token = generate_dp_token(text, entity_type=entity_type)
    ciphertext = crypto.encrypt(text)
    effective_ttl = ttl or DEFAULT_TTL

    # Collision Detection — refuse to overwrite a different plaintext under the same token
    existing_ciphertext = await async_vault.retrieve(token)
    if existing_ciphertext is not None:
        existing_hash = await async_vault.get_pt_hash_for_token(token) if hasattr(async_vault, 'get_pt_hash_for_token') else None
        if existing_hash and existing_hash != pt_hash:
            raise TokenCollisionError(
                token=token,
                existing_hash=existing_hash,
                incoming_hash=pt_hash,
            )

    await async_vault.store(token, ciphertext, effective_ttl, pt_hash, metadata=metadata)

    if search_buckets:
        for b_type in search_buckets:
            if b_type == "numeric":
                b_val = BucketManager.numeric_bucket(text, search_bucket_size)
            else:
                b_val = BucketManager.date_bucket(text, b_type)
            b_hash = BucketManager.get_bucket_index(b_val)
            await async_vault.store(token, ciphertext, effective_ttl, b_hash)

    get_audit_logger().log("encode", token)
    return token

def detokenize_text(text: str) -> str:
    import re
    from mask_privacy.core.fpe import TOKEN_PATTERN
    
    def replace_match(match):
        try:
            return decode(match.group(0))
        except:
            return match.group(0)

    return re.sub(TOKEN_PATTERN, replace_match, text)

async def adetokenize_text(text: str) -> str:
    """Native async detokenize — decodes all tokens in text concurrently."""
    import re
    import asyncio
    from mask_privacy.core.fpe import TOKEN_PATTERN
    
    if not text or not isinstance(text, str):
        return text

    tokens = re.findall(TOKEN_PATTERN, text)
    if not tokens:
        return text

    # Decode all tokens concurrently
    async def _decode_one(tok: str) -> tuple:
        try:
            plaintext = await asyncio.to_thread(decode, tok)
            return (tok, plaintext)
        except:
            return (tok, tok)

    results = await asyncio.gather(*[_decode_one(t) for t in set(tokens)])
    
    result = text
    for tok, plaintext in results:
        if plaintext != tok:
            result = result.replace(tok, plaintext)
    
    return result

