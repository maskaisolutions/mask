/**
 * Core cryptography engine for Mask SDK.
 *
 * Supports a JSON-based Keyring for transparent key rotation:
 *   MASK_KEYRING='{"v1":"oldkey...","v2":"newkey..."}'
 * The *last* key in the JSON object is the active encryption key.
 * All keys in the keyring are available for decryption (zero-downtime rotation).
 *
 * Legacy single-key mode (MASK_ENCRYPTION_KEY) is fully mapped to key ID "default".
 *
 * Ciphertext envelope format: aes:v2:{keyId}:{base64(iv+authTag+ciphertext)}
 *
 * Uses AES-256-GCM via native Node.js crypto and Argon2id for key derivation.
 */

import { config } from '../config';
import * as cryptoNode from 'crypto';
import { getKeyProvider } from './key_provider';
import { MaskDecryptionError } from './exceptions';

// ---------------------------------------------------------------------------
// AES-256-GCM constants
// ---------------------------------------------------------------------------
const AES_KEY_BYTES = 32;       // 256 bits
const GCM_IV_BYTES = 12;        // 96-bit nonce (NIST recommended for GCM)
const GCM_AUTH_TAG_BYTES = 16;  // 128-bit auth tag
const GCM_ALGORITHM = 'aes-256-gcm';

// Envelope prefixes (in priority order for decryption)
const AES_V2_PREFIX = 'aes:v2:';          // current: aes:v2:{keyId}:{base64}
const AES_GCM_PREFIX = 'aes:v1:';         // legacy single-key
const AES_GCM_LEGACY_PREFIX = 'aes:';     // oldest legacy

// ---------------------------------------------------------------------------
// Keyring type
// ---------------------------------------------------------------------------
type Keyring = Map<string, Buffer>; // keyId -> derived AES key

export class CryptoEngine {
  private static _instance: CryptoEngine | null = null;
  private _keyring: Keyring = new Map();
  private _activeKeyId: string = 'default';
  private _indexSecret: Buffer | null = null;

  private constructor() {}

  /**
   * Return the singleton instance, initialising it if necessary.
   * Async because Argon2id key derivation is async.
   */
  public static async getInstanceAsync(): Promise<CryptoEngine> {
    if (this._instance === null) {
      this._instance = new CryptoEngine();
      await this._instance._init();
    }
    return this._instance;
  }

  /** Legacy synchronous accessor — will throw if not already initialised. */
  public static getInstance(): CryptoEngine {
    if (this._instance === null) {
      throw new Error("CryptoEngine not initialised. Call getInstanceAsync() first.");
    }
    return this._instance;
  }

  /** Clear the singleton (useful for key rotation / tests). */
  public static reset(): void {
    this._instance = null;
  }

  private async _deriveAesKey(rawKey: string, keyId: string): Promise<Buffer> {
    /**
     * Derive a 256-bit AES key from a raw key string using Argon2id.
     * Salt = KDF_SALT + tenant_id + key_id — unique per tenant and per key version.
     */
    let argon2: any;
    try {
      argon2 = require('argon2');
    } catch (e) {
      throw new Error(
        "The 'argon2' package is required for Mask SDK cryptographic operations. " +
        "Install with: npm install argon2"
      );
    }
    const kdfSaltStr = config.MASK_KDF_SALT + '-' + config.MASK_TENANT_ID + '-' + keyId;
    const kdfSaltBytes = cryptoNode.createHash('sha256').update(kdfSaltStr).digest().subarray(0, 16);
    return await argon2.hash(rawKey, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
      hashLength: AES_KEY_BYTES,
      salt: kdfSaltBytes,
      raw: true,
    }) as Buffer;
  }

  private async _init(): Promise<void> {
    /**
     * Initialize the keyring. Loading order:
     *  1. MASK_KEYRING (JSON): {"v1": "oldkey", "v2": "newkey"}
     *     Last key is treated as the active key.
     *  2. MASK_ENCRYPTION_KEY (legacy): single key mapped to ID "default".
     *  3. Dev mode: auto-generate ephemeral key if MASK_DEV_MODE=true.
     */
    let argon2: any;
    try {
      argon2 = require('argon2');
    } catch (e) {
      throw new Error("The 'argon2' package is required. Install with: npm install argon2");
    }

    const provider = getKeyProvider();

    // ── Build raw key map ─────────────────────────────────────────────────
    const rawKeys: Map<string, string> = new Map();
    let activeKeyId = 'default';

    const keyringJson = await provider.getKeyring();
    if (keyringJson) {
      let parsed: Record<string, string>;
      try {
        parsed = JSON.parse(keyringJson);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new Error('MASK_KEYRING must be a non-empty JSON object.');
        }
      } catch (e) {
        throw new Error(`Invalid MASK_KEYRING format: ${e}`);
      }
      const entries = Object.entries(parsed);
      if (entries.length === 0) throw new Error('MASK_KEYRING must contain at least one key.');
      for (const [kid, k] of entries) rawKeys.set(kid, k);
      // Last key in JSON insertion order is the active key
      activeKeyId = entries[entries.length - 1][0];
    } else {
      // Legacy single-key mode
      const keyFromProvider = await provider.getEncryptionKey();
      let key: string;
      if (!keyFromProvider) {
        if (config.MASK_DEV_MODE) {
          key = cryptoNode.randomBytes(32).toString('base64');
          process.env.MASK_ENCRYPTION_KEY = key;
          console.warn(
            "MASK_DEV_MODE is enabled. Using a generated throwaway key. " +
            "DO NOT USE THIS IN PRODUCTION — tokens will be lost on restart."
          );
        } else {
          throw new Error(
            'MASK_ENCRYPTION_KEY or MASK_KEYRING is not set. ' +
            'Set one of these, or set MASK_DEV_MODE=true for ephemeral use.'
          );
        }
      } else {
        key = keyFromProvider;
      }
      rawKeys.set('default', key);
      activeKeyId = 'default';
    }

    // ── Derive AES-256 keys for every keyring entry ───────────────────────
    this._keyring = new Map();
    for (const [kid, rawKey] of rawKeys) {
      this._keyring.set(kid, await this._deriveAesKey(rawKey, kid));
    }
    this._activeKeyId = activeKeyId;

    // ── Blind Index Secret (separate Argon2id derivation) ─────────────────
    const rawKeysArr = Array.from(rawKeys.values());
    const lastRawKey = rawKeysArr[rawKeysArr.length - 1];
    const masterKey = await provider.getMasterKey() || lastRawKey;
    const indexSaltStr = config.MASK_BLIND_INDEX_SALT + '-' + config.MASK_TENANT_ID;
    const indexSaltBytes = cryptoNode.createHash('sha256').update(indexSaltStr).digest().subarray(0, 16);
    this._indexSecret = await argon2.hash(masterKey, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
      hashLength: AES_KEY_BYTES,
      salt: indexSaltBytes,
      raw: true,
    }) as Buffer;
  }

  /** Return the secret used for HMAC-based blind indexing. */
  public async getIndexSecret(): Promise<Buffer> {
    if (!this._indexSecret) {
      await this._init();
    }
    return this._indexSecret!;
  }

  /** Encrypt plaintext using the active keyring key.
   *  Envelope format: aes:v2:{keyId}:{base64(iv+authTag+ciphertext)}
   */
  public encrypt(plaintext: string): string {
    const aesKey = this._keyring.get(this._activeKeyId);
    if (!aesKey) {
      throw new Error(`CryptoEngine: active key ID '${this._activeKeyId}' not found in keyring.`);
    }

    const iv = cryptoNode.randomBytes(GCM_IV_BYTES);
    const cipher = cryptoNode.createCipheriv(GCM_ALGORITHM, aesKey, iv);
    const plaintextBuf = Buffer.from(plaintext, 'utf8');
    const encrypted = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Zero out the plaintext buffer to minimise time-in-memory for sensitive data
    plaintextBuf.fill(0);

    const combined = Buffer.concat([iv, authTag, encrypted]);
    return `${AES_V2_PREFIX}${this._activeKeyId}:${combined.toString('base64')}`;
  }

  /** Decrypt ciphertext. Supports all historical envelope formats. */
  public decrypt(ciphertext: string): string {
    if (this._keyring.size === 0) {
      throw new Error("CryptoEngine not initialised.");
    }

    try {
      if (ciphertext.startsWith(AES_V2_PREFIX)) {
        // aes:v2:{keyId}:{base64}
        const rest = ciphertext.slice(AES_V2_PREFIX.length);
        const sep = rest.indexOf(':');
        if (sep === -1) throw new Error('Malformed aes:v2 envelope: missing key ID separator.');
        const keyId = rest.slice(0, sep);
        const b64 = rest.slice(sep + 1);
        return this._decryptAesGcm(keyId, b64);
      }

      if (ciphertext.startsWith(AES_GCM_PREFIX)) {
        // aes:v1:{base64} — implicit key ID "default"
        return this._decryptAesGcm('default', ciphertext.slice(AES_GCM_PREFIX.length));
      }

      if (ciphertext.startsWith(AES_GCM_LEGACY_PREFIX)) {
        // aes:{base64} — oldest format, implicit key ID "default"
        return this._decryptAesGcm('default', ciphertext.slice(AES_GCM_LEGACY_PREFIX.length));
      }

      // Final fallback: legacy Fernet format
      return this._decryptLegacyFernet(ciphertext);
    } catch (e) {
      console.error("Failed to decrypt vault payload. Check your MASK_ENCRYPTION_KEY / MASK_KEYRING. Inner error:", e);
      throw new MaskDecryptionError("Decryption failed");
    }
  }

  private _decryptAesGcm(keyId: string, b64: string): string {
    const aesKey = this._keyring.get(keyId);
    if (!aesKey) {
      throw new MaskDecryptionError(
        `No key found for key ID '${keyId}'. Ensure the key is present in MASK_KEYRING.`
      );
    }
    const combined = Buffer.from(b64, 'base64');
    if (combined.length < GCM_IV_BYTES + GCM_AUTH_TAG_BYTES) {
      throw new Error("Ciphertext too short for AES-GCM");
    }
    const iv = combined.subarray(0, GCM_IV_BYTES);
    const authTag = combined.subarray(GCM_IV_BYTES, GCM_IV_BYTES + GCM_AUTH_TAG_BYTES);
    const encrypted = combined.subarray(GCM_IV_BYTES + GCM_AUTH_TAG_BYTES);
    const decipher = cryptoNode.createDecipheriv(GCM_ALGORITHM, aesKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  }

  private _decryptLegacyFernet(ciphertext: string): string {
    let fernet: any;
    try {
      fernet = require('fernet');
    } catch (e) {
      throw new MaskDecryptionError(
        "Missing required optional dependency 'fernet' for legacy token decryption. " +
        "Please run 'npm install fernet' to support legacy tokens."
      );
    }
    try {
      const token = new fernet.Token({
        secret: new fernet.Secret(config.MASK_ENCRYPTION_KEY || process.env.MASK_ENCRYPTION_KEY || ''),
        token: ciphertext,
        ttl: 0
      });
      return token.decode();
    } catch (e) {
      throw new MaskDecryptionError(
        "Failed to decrypt legacy Fernet token. The key may have changed or the token is corrupt."
      );
    }
  }
}

/** Return the configured crypto engine singleton (Legacy sync wrapper). */
export function getCryptoEngine(): CryptoEngine {
  return CryptoEngine.getInstance();
}

/** Async-friendly accessor for the crypto engine. */
export async function getCryptoEngineAsync(): Promise<CryptoEngine> {
  return await CryptoEngine.getInstanceAsync();
}
