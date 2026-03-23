/**
 * Vault abstraction layer for Mask Privacy SDK.
 *
 * Provides pluggable backends for token-to-plaintext storage:
 *   - MemoryVault: In-process Map (dev/testing, single-process only)
 *   - RedisVault: Redis-backed (production, multi-pod K8s)
 *   - DynamoDBVault: AWS DynamoDB-backed (AWS-native enterprises)
 *   - MemcachedVault: Memcached-backed (lightweight distributed cache)
 *
 * The active vault is selected via the MASK_VAULT_TYPE env var.
 */

import * as process from 'process';
import * as crypto from 'crypto';
import { generateFPEToken } from './fpe';
import { looksLikeToken, TOKEN_PATTERN } from './fpe_utils';
import { getCryptoEngineAsync } from './crypto';
import { MaskVaultConnectionError } from './exceptions';
import { getAuditLogger } from '../telemetry/audit_logger';
import { BucketManager } from './search';

/**
 * Return the configured fail strategy: 'open' (default) or 'closed'.
 *
 * - open:   vault errors return null / original text (graceful).
 * - closed: vault errors raise MaskVaultConnectionError (strict).
 */

/** @internal - exported for tests */
export function _getFailStrategy(): string {
  const strategy = (process.env.MASK_FAIL_STRATEGY || "open").toLowerCase();
  return strategy;
}

/** Interface every vault backend must implement. */
export abstract class BaseVault {
  /** Persist a token → plaintext mapping with a TTL. Optionally save a reverse lookup hash. */
  abstract store(token: string, plaintext: string, ttlSeconds: number, ptHash?: string | null): Promise<void>;

  /** Return the existing unexpired token for a given plaintext hash, or null. */
  abstract getTokenByPlaintextHash(ptHash: string): Promise<string | null>;

  /** Return the plaintext for token, or null if missing/expired. */
  abstract retrieve(token: string): Promise<string | null>;

  /** Delete a token and its reverse mapping. */
  abstract delete(token: string): Promise<void>;
}

/**
 * Helper to deterministically hash plaintext for reverse lookups in distributed vaults.
 *
 * If a secret is provided (from CryptoEngine.getIndexSecret), it uses HMAC-SHA256
 * for a secure blind index. Otherwise, defaults to plain SHA-256 for backward compatibility.
 */
/** @internal - exported for tests */
export function _hashPlaintext(plaintext: string, secret?: Buffer): string {
  const trimmed = plaintext.trim();
  if (secret) {
    return crypto.createHmac('sha256', secret).update(trimmed, 'utf-8').digest('hex');
  }
  return crypto.createHash('sha256').update(trimmed, 'utf-8').digest('hex');
}

/**
 * In-memory implementation (single-process, dev / testing)
 *
 * Map-backed vault. Fast, but state is lost across processes.
 */
export class MemoryVault extends BaseVault {
  private _store: Map<string, { plaintext: string; expiry: number; ptHash: string | null }>;
  private _reverseStore: Map<string, string>;

  constructor() {
    super();
    this._store = new Map();
    this._reverseStore = new Map();
  }

  private _cleanup(): void {
    // Probabilistic cleanup: only run ~1% of the time to avoid O(N) blocking
    if (Math.random() > 0.01) {
      return;
    }

    const now = Date.now() / 1000;
    for (const [token, entry] of this._store.entries()) {
      if (now > entry.expiry) {
        this._store.delete(token);
        if (entry.ptHash && this._reverseStore.get(entry.ptHash) === token) {
          this._reverseStore.delete(entry.ptHash);
        }
      }
    }
  }

  async store(token: string, plaintext: string, ttlSeconds: number, ptHash: string | null = null): Promise<void> {
    this._cleanup();
    this._store.set(token, {
      plaintext,
      expiry: (Date.now() / 1000) + ttlSeconds,
      ptHash
    });
    if (ptHash) {
      this._reverseStore.set(ptHash, token);
    }
  }

  async getTokenByPlaintextHash(ptHash: string): Promise<string | null> {
    this._cleanup();
    const token = this._reverseStore.get(ptHash);
    if (token && this._store.has(token)) {
      return token;
    }
    return null;
  }

  async retrieve(token: string): Promise<string | null> {
    this._cleanup();
    const entry = this._store.get(token);
    if (!entry) {
      return null;
    }
    if ((Date.now() / 1000) > entry.expiry) {
      this._store.delete(token);
      if (entry.ptHash && this._reverseStore.get(entry.ptHash) === token) {
        this._reverseStore.delete(entry.ptHash);
      }
      return null;
    }
    return entry.plaintext;
  }

  async delete(token: string): Promise<void> {
    const entry = this._store.get(token);
    if (entry) {
      this._store.delete(token);
      if (entry.ptHash && this._reverseStore.get(entry.ptHash) === token) {
        this._reverseStore.delete(entry.ptHash);
      }
    }
  }
}

/**
 * Redis-backed vault for horizontally scaled deployments.
 *
 * Requires the 'ioredis' package and a reachable Redis instance.
 * Configure via:
 *     MASK_REDIS_URL  (default: redis://localhost:6379/0)
 */
export class RedisVault extends BaseVault {
  private _client: any; // ioredis.Redis

  constructor(options: any = {}) {
    super();
    try {
      const Redis = require('ioredis');
      const url = process.env.MASK_REDIS_URL || "redis://localhost:6379/0";
      this._client = new Redis(url, {
        ...options,
        // Ensure connectivity at init time
        maxRetriesPerRequest: 3
      });
      console.info(`RedisVault connected to ${url}`);
    } catch (e) {
      throw new MaskVaultConnectionError(`Failed to connect to Redis: ${e}`);
    }
  }

  async store(token: string, ciphertext: string, ttlSeconds: number, ptHash: string | null = null): Promise<void> {
    try {
      const pipeline = this._client.pipeline();
      pipeline.set(`mask:${token}`, ciphertext, 'EX', ttlSeconds);
      if (ptHash) {
        pipeline.set(`mask-rev:${ptHash}`, token, 'EX', ttlSeconds);
        pipeline.set(`mask-hash:${token}`, ptHash, 'EX', ttlSeconds);
      }
      const results = await pipeline.exec();
      if (results) {
        for (const [err] of results) {
          if (err) throw err;
        }
      }
    } catch (e) {
      if (_getFailStrategy() === "closed") {
        throw new MaskVaultConnectionError(`Redis error: ${e}`);
      }
    }
  }

  async getTokenByPlaintextHash(ptHash: string): Promise<string | null> {
    const token = await this._client.get(`mask-rev:${ptHash}`);
    if (token) {
      if (await this._client.exists(`mask:${token}`)) {
        return token;
      } else {
        await this._client.del(`mask-rev:${ptHash}`);
      }
    }
    return null;
  }

  async retrieve(token: string): Promise<string | null> {
    return await this._client.get(`mask:${token}`);
  }

  async delete(token: string): Promise<void> {
    const ptHash = await this._client.get(`mask-hash:${token}`);
    const pipeline = this._client.pipeline();
    pipeline.del(`mask:${token}`);
    pipeline.del(`mask-hash:${token}`);
    if (ptHash) {
      pipeline.del(`mask-rev:${ptHash}`);
    }
    await pipeline.exec();
  }
}

/**
 * AWS DynamoDB-backed vault for AWS-native enterprise deployments.
 */
export class DynamoDBVault extends BaseVault {
  private _client: any;
  private _tableName: string;
  private _region: string;

  constructor() {
    super();
    const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
    const { DynamoDBDocument } = require('@aws-sdk/lib-dynamodb');
    this._region = process.env.MASK_DYNAMODB_REGION || "us-east-1";
    this._tableName = process.env.MASK_DYNAMODB_TABLE || "mask-vault";
    
    const baseClient = new DynamoDBClient({ region: this._region });
    this._client = DynamoDBDocument.from(baseClient);
    console.info(`DynamoDBVault connected to table ${this._tableName} in ${this._region}`);
  }

  async store(token: string, ciphertext: string, ttlSeconds: number, ptHash: string | null = null): Promise<void> {
    const { TransactWriteCommand, PutCommand } = require('@aws-sdk/lib-dynamodb');
    const now = Math.floor(Date.now() / 1000);
    const ttlVal = now + ttlSeconds;
    const item = {
      token: `mask:${token}`,
      ciphertext: ciphertext,
      ttl: ttlVal,
      ptr_hash: ptHash || undefined
    };

    if (ptHash) {
      try {
        await this._client.send(new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this._tableName,
                Item: {
                  token: `mask:${token}`,
                  ciphertext: ciphertext,
                  ttl: ttlVal,
                  ptr_hash: ptHash
                }
              }
            },
            {
              Put: {
                TableName: this._tableName,
                Item: {
                  token: `mask-rev:${ptHash}`,
                  ciphertext: token,
                  ttl: ttlVal
                }
              }
            }
          ]
        }));
      } catch (e: any) {
        console.error(`DynamoDB transact_write_items failed: ${e}`);
        // In both strategies, we must raise for DynamoDB failures to prevent data loss
        // since we didn't perform the atomic write.
        throw new MaskVaultConnectionError(`DynamoDB atomic write failed: ${e}`);
      }
    } else {
      // Single store (no reverse index)
      try {
        await this._client.send(new PutCommand({ TableName: this._tableName, Item: item }));
      } catch (e: any) {
        if (_getFailStrategy() === "closed") {
          throw new MaskVaultConnectionError(`DynamoDB individual write failed: ${e}`);
        }
      }
    }
  }

  async getTokenByPlaintextHash(ptHash: string): Promise<string | null> {
    const { GetCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');
    const now = Math.floor(Date.now() / 1000);
    const resp = await this._client.send(new GetCommand({
      TableName: this._tableName,
      Key: { token: `mask-rev:${ptHash}` }
    }));
    const item = resp.Item;
    if (!item) return null;
    if (now > (item.ttl || 0)) {
      await this._client.send(new DeleteCommand({ TableName: this._tableName, Key: { token: `mask-rev:${ptHash}` } }));
      return null;
    }
    const token = item.ciphertext;
    return (await this.retrieve(token)) !== null ? token : null;
  }

  async retrieve(token: string): Promise<string | null> {
    const { GetCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');
    const now = Math.floor(Date.now() / 1000);
    const resp = await this._client.send(new GetCommand({
      TableName: this._tableName,
      Key: { token: `mask:${token}` }
    }));
    const item = resp.Item;
    if (!item) return null;
    if (now > (item.ttl || 0)) {
      const ptHash = item.ptr_hash;
      if (ptHash) {
        await this._client.send(new DeleteCommand({ TableName: this._tableName, Key: { token: `mask-rev:${ptHash}` } }));
      }
      await this._client.send(new DeleteCommand({ TableName: this._tableName, Key: { token: `mask:${token}` } }));
      return null;
    }
    return item.ciphertext;
  }

  async delete(token: string): Promise<void> {
    const { GetCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');
    const resp = await this._client.send(new GetCommand({
      TableName: this._tableName,
      Key: { token: `mask:${token}` }
    }));
    const item = resp.Item;
    if (item && item.ptr_hash) {
      await this._client.send(new DeleteCommand({ TableName: this._tableName, Key: { token: `mask-rev:${item.ptr_hash}` } }));
    }
    await this._client.send(new DeleteCommand({ TableName: this._tableName, Key: { token: `mask:${token}` } }));
  }
}

/**
 * Memcached-backed vault.
 */
export class MemcachedVault extends BaseVault {
  private _client: any;

  constructor(options: any = {}) {
    super();
    try {
      const memjs = require('memjs');
      const host = process.env.MASK_MEMCACHED_HOST || "localhost";
      const port = process.env.MASK_MEMCACHED_PORT || "11211";
      this._client = memjs.Client.create(`${host}:${port}`, options);
      console.info(`MemcachedVault connected to ${host}:${port}`);
    } catch (e) {
      throw new MaskVaultConnectionError(`Failed to connect to Memcached: ${e}`);
    }
  }

  async store(token: string, ciphertext: string, ttlSeconds: number, ptHash: string | null = null): Promise<void> {
    try {
        await this._client.set(`mask:${token}`, Buffer.from(ciphertext), { expires: ttlSeconds });
        if (ptHash) {
           await this._client.set(`mask-rev:${ptHash}`, Buffer.from(token), { expires: ttlSeconds });
           await this._client.set(`mask-hash:${token}`, Buffer.from(ptHash), { expires: ttlSeconds });
        }
    } catch (e) {
        if (_getFailStrategy() === "closed") {
            throw new MaskVaultConnectionError(`Memcached error: ${e}`);
        }
    }
  }

  async getTokenByPlaintextHash(ptHash: string): Promise<string | null> {
    try {
        const { value } = await this._client.get(`mask-rev:${ptHash}`);
        if (!value) return null;
        const token = value.toString();
        return (await this.retrieve(token)) !== null ? token : null;
    } catch (e) {
        return null;
    }
  }

  async retrieve(token: string): Promise<string | null> {
    try {
        const { value } = await this._client.get(`mask:${token}`);
        return value ? value.toString() : null;
    } catch (e) {
        return null;
    }
  }

  async delete(token: string): Promise<void> {
    try {
        const { value } = await this._client.get(`mask-hash:${token}`);
        const ptHash = value ? value.toString() : null;
        await this._client.delete(`mask:${token}`);
        await this._client.delete(`mask-hash:${token}`);
        if (ptHash) {
          await this._client.delete(`mask-rev:${ptHash}`);
        }
    } catch (e) {}
  }
}

// Singleton accessor

let _vaultInstance: BaseVault | null = null;
const DEFAULT_TTL = parseInt(process.env.MASK_VAULT_TTL || "600");

export function getVault(): BaseVault {
  if (_vaultInstance === null) {
    const vaultType = (process.env.MASK_VAULT_TYPE || "memory").toLowerCase();
    switch (vaultType) {
      case "redis":
        _vaultInstance = new RedisVault();
        break;
      case "memory":
        _vaultInstance = new MemoryVault();
        break;
      case "dynamodb":
        _vaultInstance = new DynamoDBVault();
        break;
      case "memcached":
        _vaultInstance = new MemcachedVault();
        break;
      default:
        throw new Error(`Unknown MASK_VAULT_TYPE='${vaultType}'. Supported values: 'memory', 'redis', 'dynamodb', 'memcached'.`);
    }
    console.info(`Vault initialised: ${_vaultInstance.constructor.name}`);
  }
  return _vaultInstance;
}

export function resetVault(): void {
  _vaultInstance = null;
}

// Public convenience API (encode / decode)

export type EncodeOptions = {
    ttl?: number;
    searchBuckets?: ('year' | 'month' | 'day' | 'numeric')[];
    searchBucketSize?: number;
};

/**
 * Tokenise rawText, encrypt it, store in vault, return the FPE token.
 */
export async function encode(rawText: string, options: EncodeOptions = {}): Promise<string> {
  if (looksLikeToken(rawText)) {
    return rawText;
  }

  const text = rawText.trim();
  const vault = getVault();
  const cryptoEngine = await getCryptoEngineAsync();
  const indexSecret = await cryptoEngine.getIndexSecret();
  
  const ptHash = _hashPlaintext(text, indexSecret);

  // 1. Deduplication check
  const existingToken = await vault.getTokenByPlaintextHash(ptHash);
  if (existingToken) {
    if (await vault.retrieve(existingToken) !== null) {
      getAuditLogger().log("dedup", existingToken);
      return existingToken;
    }
  }

  // 2. Generate new token
  const token = await generateFPEToken(text);

  // 3. Encrypt the plaintext before it touches the vault
  const ciphertext = cryptoEngine.encrypt(text);

  // 4. Store with primary reverse lookup hash
  const ttl = options.ttl || DEFAULT_TTL;
  await vault.store(token, ciphertext, ttl, ptHash);

  // 5. Store additional blind indices if buckets are requested
  if (options.searchBuckets && options.searchBuckets.length > 0) {
      for (const bType of options.searchBuckets) {
          let bucketVal: string;
          if (bType === 'numeric') {
              bucketVal = BucketManager.numericBucket(text, options.searchBucketSize || 10);
          } else {
              bucketVal = BucketManager.dateBucket(text, bType);
          }
          const bHash = await BucketManager.getBucketIndex(bucketVal);
          await vault.store(token, ciphertext, ttl, bHash);

      }
  }

  getAuditLogger().log("encode", token);
  return token;
}

/** Legacy / Sync-friendly wrapper for MemoryVault only.
 * @deprecated Use encode() which is async.
 */
export function encodeSync(rawText: string, options: { ttl?: number } = {}): string {
    throw new Error("encodeSync is deprecated and unsupported in the new async architecture. Use encode().");
}

/** Async wrapper for encode (parity with Python aencode). */
export const aencode = encode;

export class DecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecodeError';
  }
}

/**
 * Detokenise token via vault lookup and decrypt it.
 */
export async function decode(token: string): Promise<string> {
  const ciphertext = await getVault().retrieve(token);
  if (ciphertext === null) {
    throw new DecodeError("Token not found or expired");
  }

  try {
    const crypto = await getCryptoEngineAsync();
    const result = crypto.decrypt(ciphertext);
    getAuditLogger().log("decode", token);
    return result;
  } catch (e) {
    throw new DecodeError("Failed to decrypt token payload");
  }
}

/** Async wrapper for decode (parity with Python adecode). */
export const adecode = decode;

/**
 * Internal helper used by integrations that prefer lenient semantics.
 */
export async function _decodeLenient(token: string): Promise<string> {
  try {
    return await decode(token);
  } catch (e) {
    return token;
  }
}

/**
 * Find all Mask tokens within text and replace them with their original plaintext.
 */
export async function detokenizeText(text: string): Promise<string> {
  if (!text || typeof text !== 'string') {
    return text;
  }

  const tokens = text.match(TOKEN_PATTERN) || [];
  let result = text;
  
  for (const token of tokens) {
      const plaintext = await _decodeLenient(token);
      if (plaintext !== token) {
        // Use global regex to replace all occurrences of this token
        // Escape the token to safely use in a regex
        const escapedToken = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        result = result.replace(new RegExp(escapedToken, 'g'), plaintext);
      }
  }
  
  return result;
}

/** Async wrapper for detokenizeText (parity with Python adetokenize_text). */
export const adetokenizeText = detokenizeText;
