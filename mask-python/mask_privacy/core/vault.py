"""
Vault abstraction layer for Mask Privacy SDK.
"""

import os
import time
import hmac
import hashlib
import logging
import threading
from typing import Dict, Any, Optional, List, Union, Literal

from mask_privacy.core.fpe import looks_like_token, generate_fpe_token
from mask_privacy.core.crypto import get_crypto_engine
from mask_privacy.core.exceptions import MaskVaultConnectionError, MaskDecryptionError
from mask_privacy.telemetry.audit_logger import get_audit_logger
from mask_privacy.core.search import BucketManager

class DecodeError(Exception):
    """Raised when a token cannot be decoded/decrypted."""
    pass

logger = logging.getLogger("mask.vault")

def _get_fail_strategy() -> str:
    return os.environ.get("MASK_FAIL_STRATEGY", "open").lower()

def _hash_plaintext(plaintext: str, secret: Optional[bytes] = None) -> str:
    """Deterministically hash plaintext for reverse lookups."""
    trimmed = plaintext.strip()
    if secret:
        return hmac.new(secret, trimmed.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(trimmed.encode("utf-8")).hexdigest()


class BaseVault:
    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        raise NotImplementedError

    def get_token_by_plaintext_hash(self, pt_hash: str) -> Optional[str]:
        raise NotImplementedError

    def retrieve(self, token: str) -> Optional[str]:
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
        # Probabilistic cleanup: only scan O(N) entries ~1% of the time to avoid blocking
        if random.random() > 0.01:
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

    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        self._cleanup()
        with self._lock:
            if token not in self._store:
                self._store[token] = {
                    "ciphertext": ciphertext,
                    "expiry": time.time() + ttl_seconds,
                    "pt_hashes": set()
                }
            
            entry = self._store[token]
            entry["ciphertext"] = ciphertext  # update if already exists
            entry["expiry"] = time.time() + ttl_seconds
            
            if pt_hash:
                entry["pt_hashes"].add(pt_hash)
                self._reverse_store[pt_hash] = token

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
            url = os.environ.get("MASK_REDIS_URL", "redis://localhost:6379/0")
            self._client = redis.from_url(url, decode_responses=True, **options)
            self._client.ping()
            logger.info("RedisVault connected to %s", url)
        except Exception as e:
            raise MaskVaultConnectionError(f"Failed to connect to Redis: {e}")

    def store(self, token: str, ciphertext: str, ttl_seconds: int, pt_hash: Optional[str] = None) -> None:
        try:
            pipe = self._client.pipeline()
            pipe.setex(f"mask:{token}", ttl_seconds, ciphertext)
            if pt_hash:
                pipe.setex(f"mask-rev:{pt_hash}", ttl_seconds, token)
                pipe.setex(f"mask-hash:{token}", ttl_seconds, pt_hash)
            pipe.execute()
        except Exception as e:
            if _get_fail_strategy() == "closed":
                raise MaskVaultConnectionError(f"Redis write failed: {e}")

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
        except:
            pass


class DynamoDBVault(BaseVault):
    """AWS DynamoDB-backed vault."""

    def __init__(self):
        try:
            import boto3
            self._region = os.environ.get("MASK_DYNAMODB_REGION", "us-east-1")
            self._table_name = os.environ.get("MASK_DYNAMODB_TABLE", "mask-vault")
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
                if _get_fail_strategy() == "closed":
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
        except:
            pass


class MemcachedVault(BaseVault):
    """Memcached-backed vault."""

    def __init__(self, **options: Any):
        try:
            from pymemcache.client.base import Client
            host = os.environ.get("MASK_MEMCACHED_HOST", "localhost")
            port = int(os.environ.get("MASK_MEMCACHED_PORT", "11211"))
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
            if _get_fail_strategy() == "closed":
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
        except:
            pass


# Singleton accessor

_vault_instance: Optional[BaseVault] = None
DEFAULT_TTL = int(os.environ.get("MASK_VAULT_TTL", "600"))

def get_vault() -> BaseVault:
    global _vault_instance
    if _vault_instance is None:
        vault_type = os.environ.get("MASK_VAULT_TYPE", "memory").lower()
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

def encode(text: str, ttl: Optional[int] = None, search_buckets: Optional[List[str]] = None, search_bucket_size: int = 10) -> str:
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
    token = generate_fpe_token(text)
    ciphertext = crypto.encrypt(text)
    effective_ttl = ttl or DEFAULT_TTL

    # 3. Store primary record
    vault.store(token, ciphertext, effective_ttl, pt_hash)

    # 4. Search buckets
    if search_buckets:
        for b_type in search_buckets:
            if b_type == "numeric":
                b_val = BucketManager.numeric_bucket(text, search_bucket_size)
            else:
                b_val = BucketManager.date_bucket(text, b_type)
            b_hash = BucketManager.get_bucket_index(b_val)
            # Store ADDITIONAL reverse mapping for the SAME token
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

def adecode(token: str):
    import asyncio
    return asyncio.to_thread(decode, token)

def aencode(text: str, **kwargs):
    import asyncio
    return asyncio.to_thread(encode, text, **kwargs)

def detokenize_text(text: str) -> str:
    import re
    from mask_privacy.core.fpe import TOKEN_PATTERN
    
    def replace_match(match):
        try:
            return decode(match.group(0))
        except:
            return match.group(0)

    return re.sub(TOKEN_PATTERN, replace_match, text)

def adetokenize_text(text: str):
    import asyncio
    return asyncio.to_thread(detokenize_text, text)
